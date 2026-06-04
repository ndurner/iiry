# IIRY

IIRY seeks to help confirm **Is It Really You?**

The hackathon MVP binds a German EUDI Wallet Verifiable Presentation to a screenshot-like JPEG. The useful security claim is deliberately narrow:

> This exact image was bound to a fresh EUDI Wallet holder presentation for the disclosed identity attributes, and the binding verified.

IIRY does **not** prove that a WhatsApp account belongs to the wallet holder, that the screenshot content is true, or that a bank-transfer request is legitimate. It proves image binding, credential presentation verification, and freshness.

## Parts

- `ios/IIRY.swiftpm`: SwiftUI iPhone app and the shared `IIRYCore` code.
- `Sources/IIRYCLI`: CLI that uses the same `IIRYCore` package as the iPhone app.
- `service/iiry_service`: FastAPI relying-party service for OpenID4VP / German EUDI Wallet callbacks.
- `docs/cawg-eudi-extension.md`: lean CAWG extension proposal for OpenID4VP holder-bound EUDI presentations.

## Core Idea

CAWG's draft VC+VP identity assertion currently centers the `cawg.verifiable_credential_binding` signature type for W3C Verifiable Credentials / Presentations. The German EUDI Wallet flow used here returns an OpenID4VP presentation, currently expected as `dc+sd-jwt` PID evidence with a Key Binding JWT. That is not the same object shape as the CAWG draft's W3C VC/VP binding.

IIRY therefore uses an extension signature type:

```text
io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v1
```

The extension keeps the CAWG idea of an identity assertion that references the C2PA hard-binding assertion, but the holder proof is validated through OpenID4VP semantics:

1. Verify the C2PA manifest and hard binding for the JPEG.
2. Read the IIRY/CAWG OpenID4VP assertion.
3. Decode the OpenID4VP nonce payload.
4. Verify that the nonce contains both:
   - a digest of the C2PA asset-binding material, and
   - a fresh random nonce.
5. Verify the Wallet presentation holder binding over the same nonce.
6. Verify issuer trust, disclosure integrity, audience, freshness, and policy.

This uses the OpenID4VP `nonce` parameter for two purposes at the same time: it is the replay-prevention nonce, and it is a domain-separated commitment to the C2PA hash / hard-binding context.

## Nonce Payload

The nonce passed in the OpenID4VP request is:

```text
base64url(deterministic-cbor([
  "io.github.ndurner.iiry.openid4vp-nonce.v1",
  1,
  random_256_bits,
  sha256(c2pa_asset_binding_material),
  sha256(optional_request_context)
]))
```

The random value prevents replay. The asset-binding digest binds the Wallet holder proof to the screenshot. The optional request-context digest can bind a parent challenge such as `Is it really you?` plus date and nonce.

## File Naming

The app exports a branded transport file instead of relying on messengers to preserve JPEG metadata:

```text
IIRY-proof-YYYY-MM-DD-ABCD1234.iiry
```

`.iiry` is intentionally less technical than `.c2pa`, avoids promising that every carrier is a raw C2PA manifest, and lets iOS route the file back into the IIRY app through the share sheet. The carrier contains the JPEG bytes and IIRY proof bundle. When a real C2PA signer is configured, the CLI can also emit a C2PA-augmented JPEG.

## C2PA Status

The CLI integrates with local `c2patool` when available. A production-quality iPhone implementation must use a real C2PA signing implementation or signer service; it must not hand-roll JPEG/JUMBF or claim-signature bytes. The Swift app currently creates and verifies the `.iiry` carrier using the same proof and nonce code as the CLI, and treats embedded C2PA signing as an explicit integration boundary.

This is intentional. A fake or unsigned C2PA-looking blob would be worse than no C2PA claim in a security-conscious hackathon.

## Web Service Serialization

The service can persist decrypted wallet presentation results for local CLI testing, but only when explicitly enabled:

```bash
IIRY_SERIALIZE_PRESENTATIONS=1
```

By default it stores sessions only and does not write serialized VP artifacts for reuse.

## Build

Build and test the Swift core and CLI:

```bash
swift test
swift run iiry --help
```

Run the service:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r service/requirements.txt
uvicorn iiry_service.app:app --app-dir service --reload --port 8110
```

The service expects RP key and German EUDI sandbox certificate material through environment variables or `service/secrets/`, matching the structure described in `service/iiry_service/app.py`.

## References

- CAWG Identity Assertion draft VC+VP profile: https://cawg.io/identity/1.3-draft+vc-vp/
- C2PA Technical Specification 2.3: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html
- OpenID4VP 1.0 final: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
