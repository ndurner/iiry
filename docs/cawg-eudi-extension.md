# IIRY CAWG Extension for German EUDI Wallet Presentations

This note describes a narrow Creator Assertions Working Group (CAWG) identity assertion extension for IIRY.

It is derived from the repository namespace:

```text
io.github.ndurner.iiry
```

## Problem

[CAWG Identity Assertion 1.3 draft + VC/VP](https://cawg.io/identity/1.3-draft+vc-vp/) adds `cawg.verifiable_credential_binding` for W3C Verifiable Credentials and Verifiable Presentations. The German EUDI Wallet hackathon flow is OpenID4VP and currently works as a holder-bound `dc+sd-jwt` PID presentation.

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
    "type": "io.github.ndurner.iiry.openid4vp-nonce.v2",
    "version": 2,
    "random_nonce_b64u": "...",
    "asset_binding_sha256_b64u": "..."
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

## Prototype Status

The current Swift core creates a constrained IIRY JPEG/C2PA profile. It writes JPEG APP11 C2PA/JUMBF segments, a CBOR `c2pa.hash.data` assertion over the JPEG bytes excluding the APP11 C2PA ranges, the IIRY proof-bundle assertion, a CBOR `c2pa.claim.v2`, and a detached COSE_Sign1 ES256 C2PA claim signature over those claim bytes.

The app and CLI use the same Swift implementation. The web service does not process JPEG bytes and does not execute `c2patool`.

The claim signature currently uses the development-only ES256 sample certificate/key material bundled with `c2patool` / `c2pa-rs`. Therefore `c2patool -d` should parse the manifest and validate `assertion.dataHash.match`, `assertion.hashedURI.match`, and `claimSignature.validated`, but still report `signingCredential.untrusted` unless the verifier is deliberately configured to trust the sample CA. The CLI option `--trust-c2pa-sample` performs that local-development trust configuration and should yield `validation_state: Trusted` for the C2PA layer. Generic C2PA tooling will still not validate the proposed CAWG/OpenID4VP proof-bundle semantics without extension support.

## Nonce Binding

The OpenID4VP `nonce` is:

```text
base64url(deterministic-cbor([
  "io.github.ndurner.iiry.openid4vp-nonce.v2",
  2,
  random_256_bits,
  sha256(c2pa_asset_binding_material)
]))
```

The nonce is the OpenID4VP transaction challenge and an image-binding commitment. The random value supports replay prevention; the asset-binding digest makes the Wallet holder-binding proof commit to the image-binding material.

The human challenge text, date, and short code are not included as a separate request-context digest. They must be visible in the JPEG and checked by the receiver. If the challenge is absent from the image, the protocol still proves image binding to a Wallet presentation, but not that the image answers a particular parent challenge.

Do not make the nonce depend on bytes that will later change when the C2PA manifest or IIRY assertion is inserted. The digest must cover asset hard-binding material that the final IIRY profile verifier, and eventually a full C2PA validator, can recompute or validate.

## Validation

Prototype IIRY profile validation succeeds only if all checks pass:

1. The JPEG contains exactly one IIRY C2PA/JUMBF profile.
2. The `c2pa.hash.data` assertion validates against the JPEG bytes after excluding the embedded C2PA APP11 ranges.
3. The CBOR claim's hashed assertion references match the embedded assertions.
4. The C2PA COSE claim signature validates over the CBOR claim bytes.
5. The IIRY nonce payload decodes with the expected namespace and version.
6. The nonce payload's asset-binding digest matches the image-binding material.
7. The OpenID4VP presentation evidence is holder-bound to the same nonce according to the service verification summary.
8. Issuer trust and disclosed-claim policy satisfy the configured German EUDI policy.

Production Content Credentials validation remains stricter and will require:

1. A C2PA claim signature that validates as COSE.
2. A non-sample signing credential trusted by the verifier policy.
3. CAWG `referenced_assertions` that use the final standard hashed URI for the hard-binding assertion.
4. Independent SD-JWT VC issuer signature, disclosures, key-binding JWT, `aud`, `nonce`, and `sd_hash` verification at receiver time.
5. Credential status and freshness checks.

## Privacy

Embedding the decrypted Wallet presentation in a JPEG can leak identity attributes. IIRY should request minimal attributes and clearly distinguish:

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
