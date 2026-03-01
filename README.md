# glasskeys

[![Package Version](https://img.shields.io/hexpm/v/glasskeys)](https://hex.pm/packages/glasskeys)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/glasskeys/)

A Gleam library for server-side verification of WebAuthn/FIDO2 credentials. Implement passwordless authentication using passkeys and security keys.

## Installation

```sh
gleam add glasskeys
```

## Quick Start

glasskeys generates JSON that is compatible with [SimpleWebAuthn](https://simplewebauthn.dev/) and the native WebAuthn API. It handles all encoding/decoding internally.

### Registration (creating a new credential)

```gleam
import glasskeys
import glasskeys/registration

pub fn handle_registration_start(username: String, user_id: BitArray) {
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "My App"),
      user: registration.User(id: user_id, name: username, display_name: username),
      origin: "https://example.com",
    )

  // Returns JSON string + challenge to store in session
  let #(options_json, challenge) = registration.generate_options(options)
  #(options_json, challenge)
}

pub fn handle_registration_finish(
  response_json: String,
  challenge: registration.Challenge,
) {
  case registration.verify(response_json:, challenge:) {
    Ok(credential) -> {
      // Store the credential:
      //   - credential.id (unique identifier)
      //   - credential.public_key (for signature verification)
      //   - credential.sign_count (for clone detection)
      Ok(credential)
    }
    Error(e) -> Error(e)
  }
}
```

### Authentication (verifying an existing credential)

```gleam
import glasskeys
import glasskeys/authentication

pub fn handle_authentication_start() {
  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [],  // Empty for discoverable credentials
    )

  let #(options_json, challenge) = authentication.generate_options(options)
  #(options_json, challenge)
}

pub fn handle_authentication_finish(
  response_json: String,
  challenge: authentication.Challenge,
  stored_credential: glasskeys.Credential,
) {
  case authentication.verify(response_json:, challenge:, stored: stored_credential) {
    Ok(updated_credential) -> {
      // Update the stored sign_count to detect cloned authenticators
      Ok(updated_credential)
    }
    Error(e) -> Error(e)
  }
}
```

### Discoverable Credentials (Passkeys)

For discoverable credentials where the user doesn't provide a username upfront, use `parse_response` to extract credential info for lookup:

```gleam
pub fn handle_discoverable_auth(
  response_json: String,
  challenge: authentication.Challenge,
) {
  // Parse to get credential_id and user_handle for database lookup
  case authentication.parse_response(response_json) {
    Ok(info) -> {
      // info.credential_id - look up stored credential
      // info.user_handle - optional user identifier (if present)
      // Then call verify() with the stored credential
    }
    Error(e) -> Error(e)
  }
}
```

## JSON Format Reference

If you're using the native WebAuthn API instead of SimpleWebAuthn, here's what the library expects and produces.

### Registration Options (from `generate_options`)

The library produces `PublicKeyCredentialCreationOptionsJSON`:

```json
{
  "rp": {
    "id": "example.com",
    "name": "My App"
  },
  "user": {
    "id": "dXNlci1pZC1ieXRlcw",
    "name": "alice",
    "displayName": "Alice Smith"
  },
  "challenge": "cmFuZG9tLWNoYWxsZW5nZS1ieXRlcw",
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 }
  ],
  "timeout": 60000,
  "attestation": "none",
  "authenticatorSelection": {
    "residentKey": "preferred",
    "userVerification": "preferred"
  }
}
```

All binary fields are base64url-encoded without padding.

### Registration Response (expected by `verify`)

The library expects `RegistrationResponseJSON` from the browser:

```json
{
  "id": "Y3JlZGVudGlhbC1pZA",
  "rawId": "Y3JlZGVudGlhbC1pZA",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiLi4uIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9",
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjF..."
  }
}
```

**Converting from native WebAuthn API:**

```javascript
const credential = await navigator.credentials.create({ publicKey: options });

const response = {
  id: credential.id,
  rawId: base64urlEncode(credential.rawId),
  type: credential.type,
  response: {
    clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
    attestationObject: base64urlEncode(credential.response.attestationObject),
  },
};

// Send JSON.stringify(response) to server
```

### Authentication Options (from `generate_options`)

The library produces `PublicKeyCredentialRequestOptionsJSON`:

```json
{
  "rpId": "example.com",
  "challenge": "cmFuZG9tLWNoYWxsZW5nZS1ieXRlcw",
  "timeout": 60000,
  "userVerification": "preferred",
  "allowCredentials": []
}
```

For non-discoverable flows, `allowCredentials` contains credential descriptors:

```json
{
  "allowCredentials": [
    { "type": "public-key", "id": "Y3JlZGVudGlhbC1pZA" }
  ]
}
```

### Authentication Response (expected by `verify`)

The library expects `AuthenticationResponseJSON` from the browser:

```json
{
  "id": "Y3JlZGVudGlhbC1pZA",
  "rawId": "Y3JlZGVudGlhbC1pZA",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLi4uIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
    "signature": "MEUCIQC...",
    "userHandle": "dXNlci1pZA"
  }
}
```

**Converting from native WebAuthn API:**

```javascript
const credential = await navigator.credentials.get({ publicKey: options });

const response = {
  id: credential.id,
  rawId: base64urlEncode(credential.rawId),
  type: credential.type,
  response: {
    clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
    authenticatorData: base64urlEncode(credential.response.authenticatorData),
    signature: base64urlEncode(credential.response.signature),
    userHandle: credential.response.userHandle
      ? base64urlEncode(credential.response.userHandle)
      : null,
  },
};

// Send JSON.stringify(response) to server
```

### Base64url Encoding Helper

```javascript
function base64urlEncode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

Or with modern browsers:

```javascript
function base64urlEncode(buffer) {
  return new Uint8Array(buffer).toBase64({ alphabet: 'base64url', omitPadding: true });
}
```

## Data Modeling

It is recommended to have a one-to-many relationship between users and passkeys. Each user should be able to register multiple passkeys:

**Why multiple passkeys per user?**

- **Multiple devices**: Users authenticate from phones, laptops, tablets, and security keys
- **Redundancy**: If a device is lost or broken, other passkeys still work
- **Gradual migration**: Users can add new devices before retiring old ones

**What to store for each passkey:**

| Field           | Purpose                                       | Source                                                       |
| --------------- | --------------------------------------------- | ------------------------------------------------------------ |
| `credential_id` | Unique identifier                             | From `credential.id` after registration                      |
| `public_key`    | For signature verification                    | From `credential.public_key` after registration              |
| `sign_count`    | Detect cloned authenticators                  | From `credential.sign_count`, update after each auth         |
| `user_id`       | Link to user (for discoverable credentials)  | Generated by your backend, passed to registration            |
| `friendly_name` | User-provided label ("Work laptop", "iPhone") | User provides via form input                                 |
| `created_at`    | Audit trail                                   | Set by backend at registration                               |
| `last_used_at`  | Help users identify stale passkeys            | Updated by backend after each auth                           |

## Account Recovery

Passkeys eliminate passwords but not the need for account recovery. **Always provide an escape hatch** for users who lose access to all their passkeys similar to what would happen for forgotten passwords.

**Recommended strategies:**

- **Multiple passkeys**: Encourage users to register passkeys on at least two devices
- **Recovery codes**: Generate one-time backup codes at registration (like 2FA recovery codes)
- **Email recovery**: Send a time-limited recovery link to a verified email
- **Support-assisted recovery**: Manual identity verification for high-value accounts

**Avoid:**

- Single-passkey accounts with no recovery path
- Assuming passkey sync will always work (it won't for security keys or cross-platform scenarios)

## Resources

Learn more about passkeys and WebAuthn:

- [passkeys.dev](https://passkeys.dev) — Developer-focused passkey documentation
- [SimpleWebAuthn](https://simplewebauthn.dev/) — Browser library that works with glasskeys
- [WebAuthn Guide](https://webauthn.guide) — Interactive WebAuthn explainer
- [FIDO Alliance](https://fidoalliance.org/passkeys/) — Official passkey standards body
- [W3C WebAuthn Spec](https://www.w3.org/TR/webauthn-2/) — Full specification
