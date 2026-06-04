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
- Do not hand-roll C2PA/JUMBF signing. Use `c2patool`, `c2pa-rs`, or a reviewed C2PA SDK/signer bridge.
- Treat the `.iiry` carrier as a branded transport envelope unless it contains a separately validated C2PA asset.
- Do not claim the high-level `c2patool` path has finalized the CAWG `referenced_assertions` hash for `c2pa.hash.data`; that needs lower-level signer integration.
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
- If adding C2PA embedding, verify with `c2patool -d` and never assume metadata survived messenger transport unless tested.

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
