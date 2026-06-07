# IIRY CAWG Extension for German EUDI Wallet Presentations

IIRY binds a German EUDI Wallet holder presentation to a JPEG by composing two binding mechanisms:

1. C2PA binds a signed manifest to the JPEG bytes through the asset hard-binding assertion.
2. OpenID4VP / SD-JWT VC holder binding signs a verifier nonce inside the wallet presentation.
3. IIRY makes that nonce commit to image-binding material and carries the resulting wallet evidence in a CAWG identity assertion.

The resulting artifact is a C2PA JPEG with a literal `cawg.identity` assertion. The assertion uses an IIRY-defined `signer_payload.sig_type`, references the C2PA hard-binding assertion, and carries the OpenID4VP `vp_token` evidence needed to validate the wallet holder binding.

IIRY extension identifiers use the repository namespace:

```text
io.github.ndurner.iiry
```

This document describes the IIRY v2 prototype profile and its validation semantics. It is written against CAWG Identity Assertion `1.3-draft+vc-vp`, a public working draft that extends the CAWG identity model for W3C Verifiable Credentials and Verifiable Presentations. IIRY follows the same identity-assertion extension model while defining OpenID4VP / SD-JWT VC semantics under an IIRY namespace.

## Security Claim

A valid IIRY v2 artifact supports this claim:

```text
This JPEG is cryptographically bound to a holder-bound German EUDI Wallet PID presentation for the disclosed identity attributes.
```

The claim decomposes into these checks:

- the C2PA manifest binds to the JPEG bytes through `c2pa.hash.data`;
- the C2PA claim signs the `cawg.identity` assertion and the hard-binding assertion;
- the `cawg.identity` assertion references that same hard-binding assertion;
- the identity assertion carries an OpenID4VP `vp_token` as typed evidence;
- the SD-JWT VC key-binding proof inside the presentation contains the IIRY nonce;
- the IIRY nonce commits to image-binding material derived from the same visual JPEG; and
- the wallet presentation validates under the configured German EUDI PID policy.

This is an identity-to-image binding. Authorship of surrounding messages, truth of screenshot contents, messenger-account control, messenger metadata preservation, and legal-signature intent are separate evidence questions.

## Relation to CAWG VC+VP

CAWG `1.3-draft+vc-vp` defines `cawg.verifiable_credential_binding` for W3C Verifiable Credentials and W3C Verifiable Presentations. The German EUDI Wallet hackathon flow used by IIRY is OpenID4VP and returns a holder-bound `dc+sd-jwt` PID presentation.

IIRY therefore uses the CAWG `cawg.identity` assertion structure with an IIRY-defined `signer_payload.sig_type` rather than the W3C VC/VP binding type.

The relevant CAWG extension point is `signer_payload.sig_type`: validators dispatch to a signature-type-specific validation method, and additional specifications may define their own `sig_type` values and corresponding `signature` data structures.

## Profile Identifier

IIRY v2 defines:

```text
signer_payload.sig_type =
  "io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v2"
```

The v2 profile supersedes the earlier `holder-binding.v1` prototype shape. v2 artifacts use a literal `cawg.identity` assertion and place the OpenID4VP evidence in the CAWG `signature` byte string.

## Assertion Shape

The emitted C2PA assertion is:

```text
label: cawg.identity
content type: application/cbor
```

Conceptual CBOR diagnostic form:

```text
{
  "signer_payload": {
    "sig_type": "io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v2",
    "referenced_assertions": [
      {
        "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
        "alg": "sha256",
        "hash": h'...'
      }
    ]
  },
  "signature": h'...deterministic JSON OpenID4VP evidence bytes...',
  "pad1": h''
}
```

The referenced assertion hash is the JUMBF payload hash for the embedded `c2pa.hash.data` assertion. The same hard-binding assertion is also referenced from the C2PA claim, so the C2PA layer and the CAWG identity layer point at the same image-binding assertion.

For this `sig_type`, the CAWG `signature` byte string is typed evidence rather than a COSE signature produced directly by the wallet. The wallet's holder-binding signature remains inside the SD-JWT VC key-binding JWT carried by the OpenID4VP presentation.

## Evidence Object

The IIRY v2 `signature` byte string contains deterministic JSON for the OpenID4VP evidence object:

```json
{
  "vp_token": {
    "pid-sd-jwt": [
      "<compact SD-JWT VC + disclosures + key-binding JWT>"
    ]
  }
}
```

The `vp_token` object is copied from the decoded OpenID4VP response. During C2PA JPEG generation, IIRY requires both the app-side compact presentation and the decoded OpenID4VP response JSON, then checks that the compact presentation equals the first compact presentation found in the response's `vp_token` before writing the CAWG assertion.

The `signer_payload.sig_type` defines the interpretation of this evidence:

1. select the compact `dc+sd-jwt` presentation from `vp_token`;
2. parse the issuer-signed JWT, disclosures, and key-binding JWT;
3. read the key-binding JWT `nonce`;
4. decode that nonce as an IIRY deterministic-CBOR nonce payload;
5. verify that the nonce payload commits to the image-binding material; and
6. validate the issuer signature, disclosures, holder binding, audience, SD-JWT hash binding, and issuer trust under policy.

## Asset-Bound Nonce

IIRY's OpenID4VP `nonce` is both the wallet transaction challenge and the image-binding commitment:

```text
base64url(deterministic-cbor([
  "io.github.ndurner.iiry.openid4vp-nonce.v2",
  2,
  random_nonce,
  sha256(asset_binding_material)
]))
```

For the current profile, `asset_binding_material` is the canonical JSON encoding of:

```json
{
  "type": "io.github.ndurner.iiry.asset-binding-material.v1",
  "version": 1,
  "mediaType": "image/jpeg",
  "byteLength": 123456,
  "assetSHA256B64URL": "...",
  "scope": "pre-c2pa-jpeg-bytes"
}
```

`random_nonce` is 32 bytes in normal IIRY generation. Validators reject nonce payloads whose random value is shorter than 16 bytes and require the asset-binding digest to be exactly 32 bytes.

The binding chain is:

```text
visual JPEG bytes
  -> IIRY asset-binding material
    -> IIRY OpenID4VP nonce
      -> SD-JWT VC key-binding JWT
        -> OpenID4VP vp_token evidence
          -> cawg.identity assertion
            -> C2PA claim signature
              -> C2PA JPEG
```

The human challenge text, date, and short code remain part of the user ceremony. They must be visible in the JPEG and reviewed by the receiver. The cryptographic nonce commits to the image bytes; the visible challenge lets the receiver judge whether the image answers the expected request.

## Validation Model

A complete IIRY validation report composes C2PA validation, CAWG identity profile validation, and OpenID4VP / SD-JWT VC presentation validation.

### C2PA and CAWG profile validation

An IIRY v2 C2PA/JPEG profile validator checks:

1. the JPEG contains one C2PA/JUMBF manifest store for this profile;
2. `c2pa.hash.data` validates against the JPEG bytes after excluding the embedded C2PA APP11 ranges;
3. the C2PA claim's hashed assertion references match the embedded assertions;
4. the detached COSE_Sign1 ES256 C2PA claim signature validates over the CBOR `c2pa.claim.v2` bytes;
5. the manifest carries a CBOR `cawg.identity` assertion;
6. the assertion uses `signer_payload.sig_type = io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v2`;
7. the assertion's `referenced_assertions` include the same `c2pa.hash.data` hard-binding assertion as the C2PA claim;
8. the assertion's `signature` field decodes as IIRY OpenID4VP evidence with a `vp_token` object;
9. the `vp_token` contains a compact SD-JWT VC presentation;
10. the presentation key-binding JWT contains a decodable IIRY nonce;
11. the nonce payload's asset-binding digest matches the image-binding material derived from the visual JPEG; and
12. the disclosed attributes required by the IIRY demo policy are present.

This layer establishes that the image, C2PA manifest, CAWG identity assertion, embedded wallet evidence, and IIRY nonce describe the same image-binding context.

### OpenID4VP and SD-JWT VC validation

The wallet presentation validator checks the credential semantics of the embedded `vp_token`:

1. the presentation is parseable as SD-JWT VC with key binding;
2. the issuer-signed JWT validates under the accepted algorithm and issuer public key;
3. the issuer certificate chain satisfies the German EUDI PID sandbox trust policy;
4. disclosed SD-JWT values match issuer commitments;
5. the holder key-binding JWT is signed by the holder key bound into the credential;
6. the key-binding JWT `nonce` is the IIRY asset-bound nonce;
7. the key-binding JWT `aud` matches an accepted verifier identifier;
8. the key-binding JWT `sd_hash` matches the presented issuer JWT and disclosures; and
9. JWT time claims are valid where present.

The current Swift verifier performs these checks locally when verifying a C2PA JPEG. The verification policy supplies accepted audiences and the German EUDI PID trust-list locations.

A production policy should additionally lock the expected credential identifier or `vp_token` entry, enforce accepted credential type values such as `urn:eudi:pid:de:1`, define credential status checks, and specify freshness windows beyond generic JWT time-claim validation.

## Current Implementation Mapping

The current Swift core writes a constrained IIRY JPEG/C2PA profile:

- JPEG APP11 C2PA/JUMBF segments;
- a CBOR `c2pa.hash.data` assertion;
- a CBOR `cawg.identity` assertion with the IIRY OpenID4VP signature type;
- a CBOR `c2pa.actions.v2` assertion;
- a CBOR `c2pa.claim.v2`; and
- a detached COSE_Sign1 ES256 C2PA claim signature.

The app and CLI use the same Swift implementation for nonce creation, draft proof state, C2PA insertion, C2PA reading, CAWG identity parsing, and local profile validation.

The app-side `IIRYCommitmentDraft` is an internal construction object. The interchange artifact is the C2PA JPEG with the `cawg.identity` assertion. Detached JSON `.iiry` proof carriers are no longer the interchange profile.

The web service drives the OpenID4VP relying-party flow. It creates the presentation request with the IIRY asset-bound nonce, receives the wallet response, performs server-side wallet checks for the interactive flow, and returns the decoded wallet response material to the app. It does not process JPEG bytes and does not execute `c2patool`.

The Swift verifier now re-validates the embedded wallet presentation from the C2PA JPEG, using `IIRYWalletVerificationPolicy` for the expected audience and German EUDI PID trust-list material. This makes the C2PA artifact independently wallet-verifiable for validators that implement the IIRY OpenID4VP extension profile and have access to the applicable trust-list material.

For hackathon development, the C2PA claim signature uses development ES256 sample certificate/key material from the `c2patool` / `c2pa-rs` ecosystem. This validates C2PA mechanics. Production deployments use a non-sample C2PA signing credential trusted by the verifier policy.

Generic C2PA tooling can validate the C2PA mechanics of an IIRY-generated JPEG and can see the `cawg.identity` assertion. Evaluating the OpenID4VP holder-binding semantics requires IIRY extension support.

## v1 to v2 Profile Change

`holder-binding.v1` was the first IIRY prototype shape. It stored an expanded IIRY proof bundle with nonce, policy, disclosed-claim, response JSON, and service-verification fields.

`holder-binding.v2` is the CAWG-shaped profile:

```text
cawg.identity
  signer_payload.sig_type = io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v2
  signer_payload.referenced_assertions -> c2pa.hash.data
  signature -> OpenID4VP vp_token evidence
```

IIRY v2 validators treat v1 artifacts as pre-profile artifacts and require regeneration into the v2 `cawg.identity` shape for CAWG-style validation.

## Privacy

The v2 profile carries the OpenID4VP `vp_token` inside the image's C2PA manifest. Every recipient who receives the intact C2PA JPEG can see the disclosed credential attributes carried by that presentation.

The demo policy requests:

```text
given_name
family_name
```

A production profile should minimize disclosed attributes, define retention expectations, and consider alternative evidence modes for cases where full-name disclosure is unnecessary.

Two verification modes are useful in practice:

```text
independently wallet-verifiable
```

means the artifact carries enough presentation evidence for a verifier to apply the OpenID4VP / SD-JWT VC policy itself.

```text
verifier-attested
```

means the artifact carries a signed statement from a trusted verifier that performed the wallet checks. That can reduce embedded personal data, but it makes trust in the verifier part of the security model.

## Deployment Requirements

A production deployment should define:

- C2PA signing credentials and trust anchors;
- the accepted OpenID4VP response profile;
- accepted `dc+sd-jwt` algorithms;
- the expected `vp_token` credential entry;
- the verifier identifiers accepted for key-binding JWT `aud` checks;
- German EUDI PID issuer trust-list handling;
- accepted credential type values;
- credential status and freshness rules;
- disclosed-claim policy;
- error codes for IIRY OpenID4VP holder-binding validation; and
- user-interface wording that distinguishes image/identity binding from authorship, account ownership, message truth, and legal signature semantics.

## Recommended User-Facing Claim

Use wording such as:

```text
Valid German EUDI Wallet holder presentation bound to this JPEG.
```

or:

```text
This image is bound to a verified EUDI Wallet PID presentation for the disclosed name.
```

Claims about who wrote a message, who controls a messenger account, whether the screenshot is true, whether metadata survived transport, or whether a legal signature was intended need separate proof mechanisms.
