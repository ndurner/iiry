# IIRY CAWG Extension for German EUDI Wallet Presentations

This note describes a narrow CAWG identity assertion extension for IIRY.

It is derived from the repository namespace:

```text
io.github.ndurner.iiry
```

## Problem

CAWG Identity Assertion 1.3 draft + VC/VP adds `cawg.verifiable_credential_binding` for W3C Verifiable Credentials and Verifiable Presentations. The German EUDI Wallet hackathon flow is OpenID4VP and currently works as a holder-bound `dc+sd-jwt` PID presentation.

Those are different presentation shapes. Treating the German Wallet response as the current CAWG W3C VP binding would be misleading.

## Signature Type

IIRY defines:

```text
signer_payload.sig_type =
  "io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v1"
```

The assertion is CAWG-shaped: it still has `signer_payload.referenced_assertions`, and those references must include the C2PA hard-binding assertion for the JPEG asset.

The evidence is OpenID4VP-shaped: it carries enough request and response material to verify that the wallet holder-binding proof used the same nonce.

## Evidence Object

The assertion evidence should contain:

```json
{
  "type": "io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v1",
  "format": "dc+sd-jwt",
  "nonce": "...",
  "nonce_payload": {
    "type": "io.github.ndurner.iiry.openid4vp-nonce.v1",
    "version": 1,
    "random_nonce_b64u": "...",
    "asset_binding_sha256_b64u": "...",
    "request_context_sha256_b64u": "..."
  },
  "request": {
    "client_id": "x509_hash:...",
    "response_mode": "direct_post.jwt",
    "dcql_query_sha256_b64u": "..."
  },
  "presentation": {
    "vp_token": "...",
    "presentation_submission": null
  },
  "policy": {
    "accepted_vct": ["urn:eudi:pid:de:1"],
    "accepted_claims": ["given_name", "family_name"],
    "trust_model": "German EUDI sandbox PID trust list"
  }
}
```

The exact final CBOR/JSON representation can evolve. The validation requirements below are the important part.

## Nonce Binding

The OpenID4VP `nonce` is:

```text
base64url(deterministic-cbor([
  "io.github.ndurner.iiry.openid4vp-nonce.v1",
  1,
  random_256_bits,
  sha256(c2pa_asset_binding_material),
  sha256(request_context)
]))
```

The nonce is both the actual replay-prevention nonce and the image-binding commitment. The request context can include the human challenge text, date, and nonce shown to the recipient.

Do not make the nonce depend on bytes that will later change when the C2PA manifest or IIRY assertion is inserted. The digest must cover the asset hard-binding material that the final C2PA validator can recompute.

## Validation

Validation succeeds only if all checks pass:

1. The C2PA manifest validates, including the claim-generator signature.
2. The hard-binding assertion validates against the JPEG bytes.
3. `signer_payload.referenced_assertions` includes the hard-binding assertion.
4. The IIRY nonce payload decodes with the expected namespace and version.
5. The nonce payload's asset-binding digest matches the validated C2PA hard-binding material.
6. The OpenID4VP presentation verifies as holder-bound to the same nonce.
7. The SD-JWT VC issuer signature, disclosures, key-binding JWT, `aud`, `nonce`, and `sd_hash` verify.
8. Issuer trust and credential status satisfy the configured German EUDI policy.
9. Freshness checks pass.

## Privacy

Embedding the decrypted Wallet presentation in a screenshot can leak identity attributes. IIRY should request minimal attributes and clearly distinguish:

```text
independently wallet-verifiable
```

from:

```text
IIRY service verified this presentation
```

The first requires carrying the presentation evidence. The second can be privacy-friendlier but shifts trust to the IIRY service.

## Non-Claims

The extension does not prove:

- who authored the WhatsApp messages,
- that WhatsApp preserved the image,
- that the screenshot contents are true,
- that the Wallet holder intended a legal document signature,
- qualified electronic signature semantics.

Those require separate mechanisms.
