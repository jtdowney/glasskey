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

// 1. Generate options to send to the browser
let #(options_json, challenge) =
  registration.new(
    relying_party: registration.RelyingParty(id: "example.com", name: "My App"),
    user: registration.User(id: user_id, name: username, display_name: username),
    origin: "https://example.com",
  )
  |> registration.build()
// Send options_json to the browser. On a single node, keep `challenge`
// in memory (e.g. an actor keyed by session id). For multi-node or
// signed-cookie storage, serialize with `registration.encode_challenge`
// (returns a JSON string) and hydrate with `registration.parse_challenge`.

// 2. Verify the browser's response
case registration.verify_json(response_json:, challenge:) {
  Ok(credential) -> {
    // Store credential.id, credential.public_key, and credential.sign_count
    Ok(credential)
  }
  Error(e) -> Error(e)
}
```

### Authentication

```gleam
import glasslock/authentication

// 1. Generate options to send to the browser
// (no allow_credential calls = discoverable/passkey flow)
let #(options_json, challenge) =
  authentication.new(
    relying_party_id: "example.com",
    origin: "https://example.com",
  )
  |> authentication.build()
// Send options_json to the browser. On a single node, keep `challenge`
// in memory (e.g. an actor keyed by session id). For multi-node or
// signed-cookie storage, serialize with `authentication.encode_challenge`
// (returns a JSON string) and hydrate with `authentication.parse_challenge`.

// 2. Verify the browser's response
case authentication.verify_json(response_json:, challenge:, stored: stored_credential) {
  Ok(updated_credential) -> {
    // Update the stored sign_count to detect cloned authenticators
    Ok(updated_credential)
  }
  Error(e) -> Error(e)
}
```

### Discoverable Credentials (Passkeys)

For discoverable credentials where the user doesn't provide a username upfront, parse the response with `parse_response_json`, extract lookup info with `response_info`, then verify the parsed `Response`:

```gleam
use response <- result.try(authentication.parse_response_json(response_json))
use info <- result.try(authentication.response_info(response))
// Look up stored credential by info.credential_id or info.user_handle
use stored <- result.try(lookup_credential(info.credential_id))
authentication.verify(response:, challenge:, stored:)
```

## Storing Credentials

Each user can register multiple passkeys. After registration, store per passkey:

| Field           | Source                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `credential_id` | `credential.id`                                                                                                                                  |
| `public_key`    | `glasslock.encode_public_key(credential.public_key)`. Rehydrate with `glasslock.parse_public_key` before calling `verify`.                       |
| `sign_count`    | `credential.sign_count`. Update after each authentication.                                                                                       |
| `transports`    | `credential.transports`. Pass back to `registration.exclude_credential` and `authentication.allow_credential` so the browser can route requests. |

## Supported Features

- ES256 (P-256 + SHA-256), Ed25519, and RS256 (RSA PKCS#1 v1.5 + SHA-256) signatures
- "none" attestation format
- Discoverable credentials (passkeys) and non-discoverable credentials
- User verification policies
- Sign count verification for cloned authenticator detection
- Cross-origin and top-origin verification for iframe embeds
- Test utilities via `glasslock/testing` for building WebAuthn test data
