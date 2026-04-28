# Security Policy

## Supported releases

Security fixes target the latest `1.x` release. Versions earlier than `1.0.0` are unsupported.

## Report a vulnerability

Send vulnerability reports through a [private GitHub Security Advisory](https://github.com/jtdowney/glasskey/security/advisories/new), not a public issue.

Include the affected package version and runtime, a minimal reproduction, the expected impact, and any known workaround. We aim to acknowledge reports within 48 hours, confirm the scope with the reporter, and coordinate a fix and disclosure.

## Security boundaries

`glasslock` verifies WebAuthn registration and authentication responses on Erlang or Node.js. It delegates cryptographic operations to [kryptos](https://github.com/jtdowney/kryptos), which uses Erlang/OTP's `:crypto` module on BEAM and `node:crypto` on Node.js.

`glasskey` invokes the browser's `navigator.credentials` API and performs no cryptography. Applications remain responsible for credential storage, account authorization, session management, CSRF protection, and trusted relying-party and origin configuration.

### Sign counters

After authentication, `glasslock` compares the authenticator's sign counter with the stored value. When the stored value is nonzero, the new value must be greater. A zero, equal, or lower value returns `SignCountRegression` because it may indicate a cloned authenticator.

## Supported algorithms

`glasslock` accepts ES256 (ECDSA P-256 with SHA-256, COSE -7), Ed25519 (EdDSA, COSE -8), and RS256 (RSASSA-PKCS1-v1_5 with SHA-256, COSE -257).

## Runtime requirements

On Erlang, `glasslock` requires OTP 27 or newer with current OpenSSL or LibreSSL libraries. On Node.js, use a supported LTS release.

After each authentication, glasslock compares the authenticator's reported sign count against the stored value. If the stored count is nonzero, the new count must be strictly greater than the stored count. A new count that is zero, less than the stored count, or equal to the stored count returns a `SignCountRegression` error, indicating a possible cloned authenticator.

## Supported Algorithms

- ES256: ECDSA with P-256 and SHA-256 (COSE algorithm -7)
- Ed25519: EdDSA with Ed25519 (COSE algorithm -8)
- RS256: RSASSA-PKCS1-v1_5 with SHA-256 (COSE algorithm -257)

## Runtime Requirements

### glasslock

On Erlang/OTP, use a currently supported OTP version with up-to-date OpenSSL/LibreSSL. On Node.js, use a currently supported LTS version. glasslock delegates cryptography to kryptos, which wraps `:crypto` on Erlang and `node:crypto` on Node.js.

### glasskey

Requires a browser with Web Authentication API support (`navigator.credentials`). All major browsers support WebAuthn. The library checks for `window.PublicKeyCredential` before attempting any ceremony and returns `NotSupported` if unavailable.
