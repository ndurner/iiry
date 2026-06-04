from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from jwcrypto import jwe, jwk
from pydantic import BaseModel, Field

from iiry_service.trust import verify_pid_issuer_chain_from_x5c


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
SESSIONS_PATH = DATA_DIR / "sessions.json"
EVENTS_PATH = DATA_DIR / "events.ndjson"
SERIALIZED_PRESENTATION_DIR = DATA_DIR / "presentations"


def load_dotenv() -> None:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_dotenv()


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


PUBLIC_BASE_URL = env("PUBLIC_BASE_URL", "https://iiry.ndurner.de").rstrip("/")
WALLET_DEEP_LINK_SCHEME = env("WALLET_DEEP_LINK_SCHEME", "eudi-openid4vp://")
IOS_APP_REDIRECT_SCHEME = env("IOS_APP_REDIRECT_SCHEME", "iiry")
RP_PRIVATE_KEY_PATH = Path(env("RP_PRIVATE_KEY_PATH", str(ROOT / "secrets/rp-private-key.pem")))
ACCESS_CERT_PEM_PATH = Path(env("ACCESS_CERT_PEM_PATH", str(ROOT / "secrets/access-certificate.pem")))
REGISTRATION_CERT_JWT_PATH = Path(env("REGISTRATION_CERT_JWT_PATH", str(ROOT / "secrets/registration-certificate.jwt")))
RESPONSE_MODE = env("RESPONSE_MODE", "direct_post.jwt")
SERIALIZE_PRESENTATIONS = env("IIRY_SERIALIZE_PRESENTATIONS", "0") == "1"

NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,2048}$")

app = FastAPI(title="IIRY OID4VP Service")


@dataclass
class Session:
    state: str
    api_token: str
    nonce: str
    created_at: int
    request_context: str | None = None
    request_object: str | None = None
    raw_response: str | None = None
    decrypted_response: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    disclosed_claims: dict[str, str] | None = None
    error: str | None = None


class CreatePresentationRequest(BaseModel):
    nonce: str = Field(min_length=32, max_length=2048)
    request_context: str | None = Field(default=None, max_length=4096)


def load_sessions() -> dict[str, Session]:
    if not SESSIONS_PATH.exists():
        return {}
    try:
        payload = json.loads(SESSIONS_PATH.read_text())
        return {state: Session(**item) for state, item in payload.items()}
    except Exception:
        return {}


sessions: dict[str, Session] = load_sessions()


def save_sessions() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_PATH.write_text(json.dumps({state: asdict(session) for state, session in sessions.items()}, indent=2))


def summarize_value(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 160:
        return {"length": len(value), "prefix": value[:80], "suffix": value[-40:]}
    if isinstance(value, dict):
        return {key: summarize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [summarize_value(item) for item in value]
    return value


def append_event(kind: str, payload: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    event = {"time": int(time.time()), "kind": kind, **summarize_value(payload)}
    with EVENTS_PATH.open("a") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode_bytes(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def b64url_decode_text(value: str) -> str:
    return b64url_decode_bytes(value).decode("utf-8")


def load_private_key() -> ec.EllipticCurvePrivateKey:
    key_data = RP_PRIVATE_KEY_PATH.read_bytes()
    key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("RP_PRIVATE_KEY_PATH must point to an EC private key")
    return key


def public_jwk_from_private_key(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    public_numbers = private_key.public_key().public_numbers()
    size = 32
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(public_numbers.x.to_bytes(size, "big")),
        "y": b64url(public_numbers.y.to_bytes(size, "big")),
        "alg": "ECDH-ES",
        "kid": "iiry-response-key",
        "use": "enc",
    }


def load_access_certificate() -> x509.Certificate | None:
    if not ACCESS_CERT_PEM_PATH.exists():
        return None
    return x509.load_pem_x509_certificate(ACCESS_CERT_PEM_PATH.read_bytes())


def x509_hash_client_id(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return "x509_hash:" + b64url(hashlib.sha256(der).digest())


def x5c_header(cert: x509.Certificate) -> list[str]:
    der = cert.public_bytes(serialization.Encoding.DER)
    return [base64.b64encode(der).decode("ascii")]


def load_registration_certificate() -> str | None:
    if not REGISTRATION_CERT_JWT_PATH.exists():
        return None
    return REGISTRATION_CERT_JWT_PATH.read_text().strip()


def verifier_identifier() -> str:
    cert = load_access_certificate()
    if cert is None:
        return f"redirect_uri:{PUBLIC_BASE_URL}"
    return x509_hash_client_id(cert)


def build_unsigned_request_payload(session: Session) -> dict[str, Any]:
    private_key = load_private_key()
    now = int(time.time())
    registration_certificate = load_registration_certificate()

    payload: dict[str, Any] = {
        "iss": verifier_identifier(),
        "aud": "https://self-issued.me/v2",
        "iat": now,
        "exp": now + 600,
        "response_type": "vp_token",
        "client_id": verifier_identifier(),
        "response_uri": f"{PUBLIC_BASE_URL}/oid4vp/response",
        "response_mode": RESPONSE_MODE,
        "nonce": session.nonce,
        "state": session.state,
        "dcql_query": {
            "credentials": [
                {
                    "id": "pid-sd-jwt",
                    "format": "dc+sd-jwt",
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                    ],
                    "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
                }
            ],
            "credential_sets": [{"options": [["pid-sd-jwt"]]}],
        },
        "client_metadata": {
            "jwks": {"keys": [public_jwk_from_private_key(private_key)]},
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128GCM",
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "kb-jwt_alg_values": ["ES256", "Ed25519"],
                    "sd-jwt_alg_values": ["ES256", "Ed25519"],
                }
            },
            "encrypted_response_alg_values_supported": ["ECDH-ES"],
            "encrypted_response_enc_values_supported": ["A128GCM"],
        },
    }
    if registration_certificate:
        payload["verifier_info"] = {"registration_certificate": registration_certificate}
    return payload


def build_request_object(session: Session) -> str:
    private_key = load_private_key()
    cert = load_access_certificate()
    headers: dict[str, Any] = {"typ": "oauth-authz-req+jwt", "alg": "ES256"}
    if cert is not None:
        headers["x5c"] = x5c_header(cert)

    return jwt.encode(
        build_unsigned_request_payload(session),
        private_key,
        algorithm="ES256",
        headers=headers,
    )


def deep_link_for(session: Session) -> str:
    request_uri = f"{PUBLIC_BASE_URL}/oid4vp/request.jwt/{session.state}"
    query = urlencode({"client_id": verifier_identifier(), "request_uri": request_uri})
    separator = "&" if "?" in WALLET_DEEP_LINK_SCHEME else "?"
    return f"{WALLET_DEEP_LINK_SCHEME}{separator}{query}"


def ios_app_redirect_uri(session: Session) -> str:
    encoded_base = quote(PUBLIC_BASE_URL, safe="")
    return f"{IOS_APP_REDIRECT_SCHEME}://wallet-callback/{session.state}?base={encoded_base}&token={session.api_token}"


def first_presentation(decoded_response: dict[str, Any] | None) -> str | None:
    if not decoded_response:
        return None
    vp_token = decoded_response.get("vp_token")
    if not isinstance(vp_token, dict):
        return None
    for presentations in vp_token.values():
        if isinstance(presentations, list):
            for presentation in presentations:
                if isinstance(presentation, str):
                    return presentation
        if isinstance(presentations, str):
            return presentations
    return None


def extract_disclosed_claims(decoded_response: dict[str, Any] | None) -> dict[str, str]:
    claims: dict[str, str] = {}
    presentation = first_presentation(decoded_response)
    if not presentation:
        return claims
    for part in presentation.split("~")[1:-1]:
        if not part:
            continue
        try:
            disclosure = json.loads(b64url_decode_text(part))
        except Exception:
            continue
        if isinstance(disclosure, list) and len(disclosure) >= 3 and isinstance(disclosure[1], str):
            claims[disclosure[1]] = str(disclosure[2])
    return claims


def ec_public_key_from_jwk(key: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if key.get("kty") != "EC" or key.get("crv") != "P-256":
        raise ValueError("Only P-256 EC holder keys are supported")
    x = int.from_bytes(b64url_decode_bytes(str(key["x"])), "big")
    y = int.from_bytes(b64url_decode_bytes(str(key["y"])), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_presentation(session: Session) -> dict[str, bool | str]:
    presentation = first_presentation(session.decrypted_response)
    result: dict[str, bool | str] = {
        "issuerSignature": False,
        "issuerCertificateTrusted": False,
        "disclosuresMatchIssuerCommitments": False,
        "holderSignature": False,
        "nonceMatchesChallenge": False,
        "audienceIsThisVerifier": False,
        "sdHashBindsPresentation": False,
    }
    if not presentation:
        result["error"] = "No SD-JWT presentation found"
        return result

    parts = presentation.split("~")
    if len(parts) < 3:
        result["error"] = "SD-JWT presentation must contain issuer JWT, disclosures, and key-binding JWT"
        return result

    issuer_jwt = parts[0]
    disclosures = parts[1:-1]
    key_binding_jwt = parts[-1]

    try:
        issuer_header = jwt.get_unverified_header(issuer_jwt)
        issuer_cert = x509.load_der_x509_certificate(base64.b64decode(issuer_header["x5c"][0]))
        issuer_claims = jwt.decode(
            issuer_jwt,
            issuer_cert.public_key(),
            algorithms=[issuer_header.get("alg", "ES256")],
            options={"verify_aud": False},
        )
        result["issuerSignature"] = True

        try:
            x5c_values = issuer_header.get("x5c", [])
            if not isinstance(x5c_values, list) or not all(isinstance(value, str) for value in x5c_values):
                raise ValueError("issuer JWT header has no valid x5c certificate chain")
            verify_pid_issuer_chain_from_x5c(x5c_values)
            result["issuerCertificateTrusted"] = True
        except Exception as exc:
            result["error"] = f"issuer trust: {exc}"

        signed_disclosure_hashes = set(issuer_claims.get("_sd", []))
        disclosed_hashes = {b64url(hashlib.sha256(disclosure.encode("ascii")).digest()) for disclosure in disclosures}
        result["disclosuresMatchIssuerCommitments"] = bool(disclosed_hashes) and disclosed_hashes.issubset(
            signed_disclosure_hashes
        )

        holder_public_key = ec_public_key_from_jwk(issuer_claims["cnf"]["jwk"])
        key_binding_header = jwt.get_unverified_header(key_binding_jwt)
        key_binding_claims = jwt.decode(
            key_binding_jwt,
            holder_public_key,
            algorithms=[key_binding_header.get("alg", "ES256")],
            audience=verifier_identifier(),
        )
        result["holderSignature"] = True
        result["nonceMatchesChallenge"] = key_binding_claims.get("nonce") == session.nonce
        result["audienceIsThisVerifier"] = key_binding_claims.get("aud") == verifier_identifier()

        signed_sd_jwt = "~".join([issuer_jwt, *disclosures]) + "~"
        expected_sd_hash = b64url(hashlib.sha256(signed_sd_jwt.encode("ascii")).digest())
        result["sdHashBindsPresentation"] = key_binding_claims.get("sd_hash") == expected_sd_hash
    except Exception as exc:
        result["error"] = str(exc)

    return result


def decode_wallet_response(raw_response: str) -> tuple[dict[str, Any] | None, str | None]:
    if not raw_response:
        return None, "wallet_response_empty"
    try:
        private_key = load_private_key()
        private_jwk = jwk.JWK.from_pem(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        segment_count = raw_response.count(".") + 1
        if segment_count == 5:
            token = jwe.JWE()
            token.deserialize(raw_response, key=private_jwk)
            payload = token.payload.decode("utf-8") if isinstance(token.payload, bytes) else token.payload
            if payload.count(".") == 2:
                return jwt.decode(payload, options={"verify_signature": False}), None
            return json.loads(payload), None
        if segment_count == 3:
            return jwt.decode(raw_response, options={"verify_signature": False}), None
        return None, f"unsupported_response_token_shape: {segment_count}_segments"
    except Exception as exc:
        return None, f"response_decryption_or_parsing_failed: {exc}"


def serialize_presentation_if_enabled(session: Session) -> str | None:
    if not SERIALIZE_PRESENTATIONS or session.decrypted_response is None:
        return None
    SERIALIZED_PRESENTATION_DIR.mkdir(parents=True, exist_ok=True)
    path = SERIALIZED_PRESENTATION_DIR / f"{session.state}.json"
    path.write_text(json.dumps(session.decrypted_response, indent=2, sort_keys=True) + "\n")
    return str(path)


def token_is_valid(session: Session, token: str | None, authorization: str | None) -> bool:
    if token == session.api_token:
        return True
    if authorization and authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ") == session.api_token
    return False


def session_summary(session: Session) -> dict[str, Any]:
    return {
        "state": session.state,
        "nonce": session.nonce,
        "created_at": session.created_at,
        "has_wallet_response": bool(session.raw_response),
        "claims": session.disclosed_claims or {},
        "verification": session.verification,
        "error": session.error,
        "status_url": f"{PUBLIC_BASE_URL}/api/presentations/{session.state}",
    }


@app.post("/api/presentations")
def create_presentation(request: CreatePresentationRequest) -> JSONResponse:
    if not NONCE_PATTERN.fullmatch(request.nonce):
        return JSONResponse({"error": "invalid_nonce"}, status_code=400)
    session = Session(
        state=str(uuid.uuid4()),
        api_token=secrets.token_urlsafe(32),
        nonce=request.nonce,
        request_context=request.request_context,
        created_at=int(time.time()),
    )
    sessions[session.state] = session
    save_sessions()
    append_event("session_created", {"state": session.state, "nonce_length": len(session.nonce)})
    return JSONResponse(
        {
            "state": session.state,
            "api_token": session.api_token,
            "nonce": session.nonce,
            "open_wallet_url": deep_link_for(session),
            "request_uri": f"{PUBLIC_BASE_URL}/oid4vp/request.jwt/{session.state}",
            "response_uri": f"{PUBLIC_BASE_URL}/oid4vp/response",
            "status_url": f"{PUBLIC_BASE_URL}/api/presentations/{session.state}",
            "wallet_response_url": f"{PUBLIC_BASE_URL}/api/presentations/{session.state}/wallet-response",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/api/presentations/{state}")
def get_presentation(state: str) -> JSONResponse:
    session = sessions.get(state)
    if session is None:
        return JSONResponse({"error": "unknown_state"}, status_code=404)
    return JSONResponse(session_summary(session), headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.get("/api/presentations/{state}/wallet-response")
def get_wallet_response(
    state: str,
    token: str | None = None,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    session = sessions.get(state)
    if session is None:
        return JSONResponse({"error": "unknown_state"}, status_code=404)
    if not token_is_valid(session, token, authorization):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if session.decrypted_response is None:
        return JSONResponse({"error": "wallet_response_pending", **session_summary(session)}, status_code=202)
    return JSONResponse(
        {
            **session_summary(session),
            "decoded_response": session.decrypted_response,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/oid4vp/request.jwt/{state}")
def request_object_raw(request: Request, state: str) -> PlainTextResponse:
    session = sessions.get(state)
    if session is None:
        return PlainTextResponse("unknown_state", status_code=404)
    try:
        session.request_object = build_request_object(session)
        save_sessions()
        append_event(
            "request_object_jwt",
            {
                "state": state,
                "request_length": len(session.request_object),
                "user_agent": request.headers.get("user-agent", ""),
            },
        )
    except Exception as exc:
        session.error = f"request_object_failed: {exc}"
        save_sessions()
        return PlainTextResponse(session.error, status_code=500)
    return PlainTextResponse(
        session.request_object,
        media_type="application/oauth-authz-req+jwt",
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.api_route("/oid4vp/response", methods=["GET", "POST"])
async def oid4vp_response(request: Request) -> JSONResponse:
    raw_body = await request.body()
    content_type = request.headers.get("content-type", "")
    query = dict(request.query_params)
    form: dict[str, Any] = {}

    if request.method == "GET":
        return JSONResponse({"status": "ok", "message": "Wallet responses must use POST."})

    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        parsed_form = await request.form()
        form = {key: parsed_form.get(key) for key in parsed_form.keys()}

    raw_response = form.get("response")
    if not isinstance(raw_response, str):
        raw_response = ""
    top_level_state = form.get("state") if isinstance(form.get("state"), str) else None
    decoded_response, decode_error = decode_wallet_response(raw_response)
    decoded_state = decoded_response.get("state") if isinstance(decoded_response, dict) else None
    response_state = top_level_state or decoded_state

    append_event(
        "wallet_response",
        {
            "method": request.method,
            "path": str(request.url.path),
            "content_type": content_type,
            "query": query,
            "form_keys": list(form.keys()),
            "body_length": len(raw_body),
            "raw_response_length": len(raw_response),
            "top_level_state": top_level_state,
            "decoded_state": decoded_state,
            "decode_error": decode_error,
            "user_agent": request.headers.get("user-agent", ""),
        },
    )

    target = sessions.get(response_state or "")
    if target is None:
        return JSONResponse(
            {"error": "unknown_state", "state": response_state, "decode_error": decode_error},
            status_code=400,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    target.raw_response = raw_response
    target.decrypted_response = decoded_response
    target.error = decode_error
    target.verification = verify_presentation(target) if decoded_response else None
    target.disclosed_claims = extract_disclosed_claims(decoded_response)
    serialized_path = serialize_presentation_if_enabled(target)
    save_sessions()

    return JSONResponse(
        {
            "status": "ok",
            "redirect_uri": ios_app_redirect_uri(target),
            "serialized_presentation_path": serialized_path,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
