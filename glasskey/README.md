# glasskey

[![Package Version](https://img.shields.io/hexpm/v/glasskey)](https://hex.pm/packages/glasskey)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/glasskey/)

Browser WebAuthn/FIDO2 bindings for Gleam, targeting JavaScript.

Wraps the browser's `navigator.credentials` API to perform registration and authentication ceremonies. Produces JSON compatible with [glasslock](../glasslock/) for server-side verification.

## Installation

```sh
gleam add glasskey
```

## Usage

The server (glasslock) returns a JSON envelope containing the `options` subtree. Decode that subtree with `registration_options_decoder()` or `authentication_options_decoder()`, then pass the parsed value to the ceremony starter.

### Registration

```gleam
import glasskey
import gleam/dynamic/decode
import gleam/javascript/promise

let envelope_decoder = {
  use session_id <- decode.field("session_id", decode.string)
  use options <- decode.field("options", glasskey.registration_options_decoder())
  decode.success(#(session_id, options))
}

// Decode the server envelope into (session_id, RegistrationOptions)...
let assert Ok(#(_session_id, options)) = json.parse(envelope_json, envelope_decoder)

use result <- promise.await(glasskey.start_registration(options))
case result {
  Ok(response_json) -> {
    // Send response_json to server for verification
  }
  Error(glasskey.NotSupported) -> // WebAuthn not available
  Error(glasskey.NotAllowed) -> // User cancelled
  Error(e) -> // Other error
}
```

### Authentication

```gleam
import glasskey
import gleam/javascript/promise

// options parsed via glasskey.authentication_options_decoder() (same envelope pattern).
use result <- promise.await(glasskey.start_authentication(options))
case result {
  Ok(response_json) -> {
    // Send response_json to server for verification
  }
  Error(e) -> // Handle error
}
```

### Conditional Authentication (autofill UI)

For passkey suggestions in the browser's autofill dropdown instead of a modal prompt. Requires an `<input autocomplete="username webauthn">` element on the page.

```gleam
case glasskey.start_conditional_authentication(options) {
  Ok(glasskey.ConditionalAuthentication(result:, abort:)) -> {
    // `abort` cancels the pending ceremony; call it before starting a modal flow.
    use response <- promise.await(result)
    // Send response JSON to server for verification
  }
  Error(e) -> // Handle error
}
```

### Capability Detection

```gleam
import glasskey
import gleam/javascript/promise

// Synchronous check
case glasskey.supports_webauthn() {
  True -> // WebAuthn is available
  False -> // Fall back to password auth
}

// Check for platform authenticator (Touch ID, Windows Hello, etc.)
use available <- promise.await(glasskey.platform_authenticator_available())

// Check for autofill/conditional mediation support
use available <- promise.await(glasskey.supports_webauthn_autofill())
```

## Error Types

| Error                | Meaning                                            |
| -------------------- | -------------------------------------------------- |
| `NotSupported`       | WebAuthn not available in this browser             |
| `NotAllowed`         | User cancelled or timed out                        |
| `Aborted`            | Operation was aborted                              |
| `SecurityError`      | Security policy violation (e.g., non-HTTPS origin) |
| `EncodingError(msg)` | Invalid options JSON                               |
| `UnknownError(msg)`  | Unexpected browser error                           |

## How It Works

1. Options JSON from glasslock is parsed and validated, then passed to the browser API
2. The FFI calls `navigator.credentials.create()` or `.get()`, handling `ArrayBuffer` conversion
3. The response is serialized to JSON compatible with glasslock's `verify()` functions
