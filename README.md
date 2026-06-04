# IIRY

IIRY seeks to help confirm **Is It Really You?**

The hackathon MVP creates an EUDI Wallet-backed Content Credential for a challenged JPEG image. In the WhatsApp story, that image is usually a conversation capture, but the defensible claim is **attested image provenance**, not chat forensics:

> This exact image is cryptographically bound to a fresh German EUDI Wallet holder presentation for the disclosed identity attributes, and the binding verified.

IIRY does **not** prove that a WhatsApp account belongs to the wallet holder, that the conversation content is true, or that a bank-transfer request is legitimate. It proves image binding, credential presentation verification, holder-binding freshness, and verifier policy checks.

## Parts

- `ios/IIRY.swiftpm`: SwiftUI iPhone app and the shared `IIRYCore` code.
- `cli/Sources/IIRYCLI`: macOS CLI that uses the same `IIRYCore` package as the iPhone app.
- `service/iiry_service`: FastAPI relying-party service for OpenID4VP / German EUDI Wallet callbacks and the C2PA signer bridge.
- `docs/cawg-eudi-extension.md`: lean CAWG extension proposal for OpenID4VP holder-bound EUDI presentations.

## Core Idea

[Content Credentials](https://c2pa.org/) are the user-facing provenance experience built around the technical standards from the [Coalition for Content Provenance and Authenticity (C2PA)](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html). The [Creator Assertions Working Group (CAWG)](https://cawg.io/identity/1.3-draft+vc-vp/) adds identity assertions that can bind a credentialed actor to C2PA assertions such as the asset hard binding.

CAWG's draft VC+VP identity assertion currently centers the `cawg.verifiable_credential_binding` signature type for W3C Verifiable Credentials / Presentations. The German EUDI Wallet flow used here returns an OpenID4VP presentation, currently expected as `dc+sd-jwt` PID evidence with a Key Binding JWT. That is not the same object shape as the CAWG draft's W3C VC/VP binding.

IIRY therefore uses an extension signature type:

```text
io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v1
```

The extension keeps the CAWG idea of an identity assertion that references the C2PA hard-binding assertion, but the holder proof is validated through OpenID4VP semantics:

1. Verify the C2PA manifest and hard binding for the JPEG.
2. Read the IIRY/CAWG OpenID4VP assertion.
3. Decode the OpenID4VP nonce payload.
4. Verify that the nonce contains both a digest of the C2PA asset-binding material and a fresh random nonce.
5. Verify the Wallet presentation holder binding over the same nonce.
6. Verify issuer trust, disclosure integrity, audience, freshness, and policy.

The OpenID4VP `nonce` is originally a verifier transaction challenge. In holder-bound presentations it helps bind the proof to this verifier and this transaction, preventing presentation injection and replay. In SD-JWT VC, the Key Binding JWT also uses `nonce`, `aud`, and `sd_hash` so the holder proof is fresh, intended for the verifier, and bound to the selected disclosures.

IIRY does not treat the nonce as a magic cryptographic amplifier. It makes the nonce a domain-separated structured challenge: the Wallet signs a holder-binding proof over the OpenID4VP nonce, and that nonce contains the digest of IIRY's image-binding material.

## Nonce Payload

The nonce passed in the OpenID4VP request is built like this:

```text
base64url(deterministic-cbor([
  "io.github.ndurner.iiry.openid4vp-nonce.v2",
  2,
  random_256_bits,
  sha256(c2pa_asset_binding_material)
]))
```

The random value provides the actual transaction challenge. The asset-binding digest binds the Wallet holder proof to the image commitment.

The human challenge text, for example:

```text
Is it really you?
(2026-06-04 ABCD1234)
```

is intentionally **not** part of this nonce payload. It must be visible in the image itself and checked by the receiver. If the challenge is not captured in the image, IIRY can still prove that a wallet presentation was bound to those image bytes, but it cannot prove that the image answered the parent's latest challenge.

## File Naming

The app exports a branded transport file:

```text
IIRY-Commitment-YYYY-MM-DD-ABCD1234.jpg.c2pa.cawg.iiry
```

`Commitment` is deliberate: the file contains a cryptographic commitment and evidence, not a blanket confirmation that the content is true. The `.jpg` segment keeps the ordinary image nature visible, `.c2pa.cawg` makes the technical choices visible during a no-slides demo, and the final `.iiry` extension lets iOS route the file back into IIRY. Dots are safer than `+` for document-type routing and share-sheet handling.

## C2PA Status

The shared Swift core builds the IIRY proof bundle, nonce payload, and C2PA manifest JSON. The iPhone app and CLI use that same implementation.

The CLI integrates with local `c2patool` for two C2PA paths:

- `iiry c2pa-embed <proof.iiry> --out <image.jpg>` embeds the shared manifest into a JPEG and signs it with `c2patool`.
- `iiry verify <proof.iiry|c2pa-image.jpg>` runs the app-style IIRY verifier; for C2PA JPEGs it also runs `c2patool -d` and checks the C2PA claim signature, signing-credential trust, and `c2pa.hash.data` hard binding.

The iPhone app does not hand-roll JPEG/JUMBF or C2PA claim signing. After the Wallet callback, it sends the shared manifest JSON and JPEG bytes to the service's signer bridge, which runs `c2patool`, returns the C2PA-augmented JPEG, and exposes detailed inspection for receiver-side verification. A deployment must configure a real trusted C2PA signing credential; the default `c2patool` development certificate is not sufficient for a credible demo claim.

The high-level `c2patool` manifest API still cannot safely precompute and insert the final CAWG `referenced_assertions` hashed URI for `c2pa.hash.data`; that value is produced during signing and can change between signing runs. A production implementation needs a lower-level C2PA signer integration that finalizes the IIRY/CAWG identity assertion with the exact hard-binding reference before claim signing. This prototype keeps that boundary explicit rather than fabricating a C2PA-looking claim.

## Web Service Serialization

The service can persist decrypted wallet presentation results for local CLI testing, but only when explicitly enabled:

```bash
IIRY_SERIALIZE_PRESENTATIONS=1
```

By default it stores sessions only and does not write serialized VP artifacts for reuse.

## Build

Build and test the shared Swift core and macOS CLI:

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

The service expects RP key and German EUDI sandbox certificate material through environment variables or `service/secrets/`, matching the structure described in `service/iiry_service/app.py`. Set `C2PATOOL_PATH` if `c2patool` is not on the service host's path.

## References

- [Content Credentials / C2PA](https://c2pa.org/)
- [C2PA Technical Specification 2.3](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html)
- [CAWG draft VC+VP identity assertion](https://cawg.io/identity/1.3-draft+vc-vp/)
- [OpenID4VP 1.0 final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [RFC 9901: Selective Disclosure for JWTs](https://www.rfc-editor.org/rfc/rfc9901.html)
