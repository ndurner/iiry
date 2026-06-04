from __future__ import annotations

import base64
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

PID_TRUST_LIST_URL = os.environ.get(
    "PID_TRUST_LIST_URL",
    "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt",
)
PID_TRUST_LIST_SIGNING_CERT_URL = os.environ.get(
    "PID_TRUST_LIST_SIGNING_CERT_URL",
    "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/certificate.pem",
)
PID_TRUST_LIST_PATH = Path(os.environ.get("PID_TRUST_LIST_PATH", DATA_DIR / "pid-provider-trust-list.jwt"))
PID_TRUST_LIST_SIGNING_CERT_PATH = Path(
    os.environ.get("PID_TRUST_LIST_SIGNING_CERT_PATH", DATA_DIR / "pid-provider-trust-list-signer.pem")
)

PID_ISSUANCE_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance"


class TrustValidationError(ValueError):
    pass


def fetch_text(url: str, cache_path: Path) -> str:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            text = response.read().decode("utf-8")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(text)
        return text
    except Exception:
        if cache_path.exists():
            return cache_path.read_text()
        raise


def load_trust_list_token() -> str:
    return fetch_text(PID_TRUST_LIST_URL, PID_TRUST_LIST_PATH).strip()


def load_trust_list_signing_certificate() -> x509.Certificate:
    pem = fetch_text(PID_TRUST_LIST_SIGNING_CERT_URL, PID_TRUST_LIST_SIGNING_CERT_PATH).encode("utf-8")
    return x509.load_pem_x509_certificate(pem)


def decode_and_verify_trust_list() -> dict[str, Any]:
    token = load_trust_list_token()
    signing_cert = load_trust_list_signing_certificate()
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "trustlist+jwt":
        raise TrustValidationError(f"unexpected trust-list JWT typ: {header.get('typ')}")
    payload = jwt.decode(
        token,
        signing_cert.public_key(),
        algorithms=[header.get("alg", "ES256")],
        options={"verify_aud": False},
    )
    validate_trust_list_freshness(payload)
    return payload


def validate_trust_list_freshness(payload: dict[str, Any]) -> None:
    next_update = payload.get("LoTE", {}).get("ListAndSchemeInformation", {}).get("NextUpdate")
    if not isinstance(next_update, str):
        raise TrustValidationError("trust list has no NextUpdate")
    expires_at = datetime.fromisoformat(next_update.replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= expires_at:
        raise TrustValidationError(f"trust list expired at {next_update}")


def pid_issuance_trust_anchors(payload: dict[str, Any]) -> list[x509.Certificate]:
    anchors: list[x509.Certificate] = []
    entities = payload.get("LoTE", {}).get("TrustedEntitiesList", [])
    if not isinstance(entities, list):
        return anchors
    for entity in entities:
        services = entity.get("TrustedEntityServices", []) if isinstance(entity, dict) else []
        if not isinstance(services, list):
            continue
        for service in services:
            info = service.get("ServiceInformation", {}) if isinstance(service, dict) else {}
            if info.get("ServiceTypeIdentifier") != PID_ISSUANCE_SERVICE_TYPE:
                continue
            digital_identity = info.get("ServiceDigitalIdentity", {})
            certs = digital_identity.get("X509Certificates", []) if isinstance(digital_identity, dict) else []
            if not isinstance(certs, list):
                continue
            for cert_item in certs:
                cert_value = cert_item.get("val") if isinstance(cert_item, dict) else None
                if isinstance(cert_value, str):
                    anchors.append(x509.load_der_x509_certificate(base64.b64decode(cert_value)))
    return anchors


def parse_x5c_chain(x5c_values: list[str]) -> list[x509.Certificate]:
    return [x509.load_der_x509_certificate(base64.b64decode(value)) for value in x5c_values]


def cert_fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


def certificate_is_current(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_certificate_signature(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            padding.PKCS1v15(),
            subject.signature_hash_algorithm,
        )
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(subject.signature, subject.tbs_certificate_bytes, ec.ECDSA(subject.signature_hash_algorithm))
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(subject.signature, subject.tbs_certificate_bytes)
        return
    raise TrustValidationError(f"unsupported issuer public key type: {type(public_key).__name__}")


def chain_terminates_at_trust_anchor(chain: list[x509.Certificate], anchors: list[x509.Certificate]) -> bool:
    if not chain:
        raise TrustValidationError("issuer JWT has no x5c certificate chain")
    if not anchors:
        raise TrustValidationError("PID trust list contains no issuance trust anchors")
    for cert in chain + anchors:
        if not certificate_is_current(cert):
            raise TrustValidationError(f"certificate is not currently valid: {cert.subject.rfc4514_string()}")

    candidates = chain[1:] + anchors
    current = chain[0]
    visited: set[bytes] = set()
    while True:
        current_fingerprint = cert_fingerprint(current)
        if current_fingerprint in visited:
            return False
        visited.add(current_fingerprint)
        for issuer in candidates:
            if current.issuer != issuer.subject:
                continue
            try:
                verify_certificate_signature(current, issuer)
            except Exception:
                continue
            if any(cert_fingerprint(issuer) == cert_fingerprint(anchor) for anchor in anchors):
                return True
            current = issuer
            break
        else:
            return False


def verify_pid_issuer_chain_from_x5c(x5c_values: list[str]) -> None:
    trust_list = decode_and_verify_trust_list()
    anchors = pid_issuance_trust_anchors(trust_list)
    chain = parse_x5c_chain(x5c_values)
    if not chain_terminates_at_trust_anchor(chain, anchors):
        raise TrustValidationError("issuer certificate chain does not terminate at a trusted PID issuance anchor")
