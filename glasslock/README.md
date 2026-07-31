# glasslock

[![Package Version](https://img.shields.io/hexpm/v/glasslock)](https://hex.pm/packages/glasslock)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/glasslock/)

Server-side WebAuthn/FIDO2 credential verification for Gleam.

Covers both registration and authentication ceremonies, generating challenge options for the browser and verifying the signed responses. Designed for use with [glasskey](https://hex.pm/packages/glasskey) on the browser side, or any client that produces the same JSON format (e.g. [@simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser)).

## Installation

```sh
gleam add glasslock
```

## Usage

[`glasslock/registration`](https://hexdocs.pm/glasslock/glasslock/registration.html) builds registration options and verifies registration responses. [`glasslock/authentication`](https://hexdocs.pm/glasslock/glasslock/authentication.html) builds authentication options and verifies assertions for known-user and discoverable flows.

Both builders return `#(options_json, challenge)`. Send `options_json` to the browser and retain `challenge` until the response arrives. Keep the challenge in memory on one node. To move it between processes or nodes, use the module's `encode_challenge` and `parse_challenge` functions.

After registration, insert the returned credential only if its ID is unassigned. After authentication, persist the returned `sign_count`. For discoverable credentials, use `parse_response_json` and `response_info` to load the account and stored credential, then pass the same parsed response to `verify`.

## Storing Credentials

Each user can register multiple passkeys. After registration, store per passkey:

| Field           | Source                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `credential_id` | `credential.id`                                                                                                                                  |
| `public_key`    | `glasslock.encode_public_key(credential.public_key)`. Rehydrate with `glasslock.parse_public_key` before calling `verify`.                       |
| `sign_count`    | `credential.sign_count`. Update after each authentication.                                                                                       |
| `transports`    | `credential.transports`. Pass back to `registration.exclude_credential` and `authentication.allow_credential` so the browser can route requests. |

The credential ID must be unique across every account for the RP. Enforce this
with a database uniqueness constraint: `UNIQUE (credential_id)` for one RP, or
`UNIQUE (rp_id, credential_id)` when a database serves several RPs.
