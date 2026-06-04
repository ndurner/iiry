# AGENTS

This repository is a security-sensitive hackathon prototype. Keep claims narrow and verifiable.

## Core Rule

The iPhone app and CLI must use the same shared Swift implementation for all IIRY proof mechanics:

```text
ios/IIRY.swiftpm/Sources/IIRYCore
```

Do not duplicate nonce encoding, asset hashing, proof-bundle encoding, carrier parsing, or validation logic in the app and CLI. Reproducibility of the core technical contribution depends on sameness between the two paths.

## Security Boundaries

- Do not claim that IIRY proves WhatsApp account ownership or message truth.
- Do not claim C2PA validity unless a real C2PA manifest and claim signature validate.
- The Swift core implements the constrained IIRY JPEG/C2PA profile: JPEG APP11 insertion, JUMBF boxes, `c2pa.hash.data` exclusion hashing, the IIRY proof assertion, `c2pa.claim.v2` CBOR bytes, and a detached COSE_Sign1 ES256 C2PA claim signature.
- The embedded sample ES256 certificate/key is development-only material from `c2patool` / `c2pa-rs`; it can validate mechanics but must never be described as production Content Credentials signing-credential trust.
- Do not add `/api/c2pa/*` or any service-side `c2patool` execution path. The service is OpenID4VP-only.
- Treat the `.iiry` carrier as a branded transport envelope unless it contains a locally verified IIRY profile or separately validated C2PA asset.
- Keep decrypted wallet presentations private by default. Service serialization must stay default-off behind `IIRY_SERIALIZE_PRESENTATIONS=1`.
- Keep RP private keys, access certificates, registration certificates, and serialized wallet responses out of Git.

## Namespaces

The GitHub remote is `https://github.com/ndurner/iiry.git`, so IIRY namespaces derive from:

```text
io.github.ndurner.iiry
```

Current extension identifiers:

```text
io.github.ndurner.iiry.cawg.openid4vp.holder-binding.v1
io.github.ndurner.iiry.openid4vp-nonce.v2
io.github.ndurner.iiry.proof-bundle.v1
io.github.ndurner.iiry.carrier.v1
```

## Development

- Prefer small commits: docs, shared core, CLI, service, app, tests.
- Run `swift test` before committing Swift changes.
- Run `python3 -m compileall service` before committing service changes.
- If touching OpenID4VP verification, use current official specs and be precise about SD-JWT VC versus W3C VC/VP semantics.
- If touching C2PA/JPEG embedding, run Swift adversarial tests and compare with `iiry verify <asset> --both`. The expected default `c2patool` result is `assertion.dataHash.match`, `assertion.hashedURI.match`, and `claimSignature.validated` success, with `signingCredential.untrusted`.
- Use `iiry verify <asset> --c2patool --trust-c2pa-sample` only for local conformance checks against the C2PA sample trust anchor; it should not be treated as production trust.
- Never assume metadata survived messenger transport unless tested.

## UX Copy

Use wording like:

```text
Valid EUDI Wallet holder presentation bound to this image.
```

Avoid wording like:

```text
This WhatsApp message is real.
This person sent this message.
The wallet signed the screenshot.
```

The wallet signs a holder-binding proof over the OpenID4VP nonce. IIRY makes that nonce commit to the C2PA/image-binding context.

The human challenge text (`Is it really you?` plus date and short nonce code) must be visible in the image and reviewed by the receiver. Do not reintroduce a hidden request-context digest unless the security model is deliberately changed and documented.
