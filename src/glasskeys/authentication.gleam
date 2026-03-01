//// WebAuthn authentication API compatible with SimpleWebAuthn browser.
////
//// ## Example (known credential)
////
//// ```gleam
//// import glasskeys/authentication
////
//// // Generate options for browser
//// let #(options_json, challenge) = authentication.generate_options(
////   authentication.Options(
////     rp_id: "example.com",
////     origin: "https://example.com",
////     allow_credentials: [stored_credential.id],
////     ..authentication.default_options()
////   ),
//// )
////
//// // Send options_json to browser, receive response_json back
////
//// // Verify the response
//// case authentication.verify(response_json, challenge, stored_credential) {
////   Ok(updated_credential) -> // Update stored sign_count
////   Error(e) -> // Handle error
//// }
//// ```
////
//// ## Example (discoverable/passkey)
////
//// ```gleam
//// // Generate options with empty allow_credentials
//// let #(options_json, challenge) = authentication.generate_options(
////   authentication.Options(
////     rp_id: "example.com",
////     origin: "https://example.com",
////     allow_credentials: [],
////     ..authentication.default_options()
////   ),
//// )
////
//// // Parse response to get credential_id for lookup
//// let assert Ok(info) = authentication.parse_response(response_json)
////
//// // Look up stored credential
//// let assert Ok(stored) = lookup_credential(info.credential_id)
////
//// // Verify with looked-up credential
//// case authentication.verify(response_json, challenge, stored) {
////   Ok(updated) -> // Update stored sign_count
////   Error(e) -> // Handle error
//// }
//// ```

import glasskeys.{
  type Credential, type GlasskeysError, type UserPresence, type UserVerification,
  Credential, CredentialNotAllowed, ParseError, PresenceRequired,
  SignCountRegression, UserPresenceFailed, UserVerificationFailed,
  VerificationDiscouraged, VerificationMismatch, VerificationPreferred,
  VerificationRequired,
}
import glasskeys/internal
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import kryptos/crypto
import kryptos/hash

/// Options for authentication challenge generation.
pub type Options {
  Options(
    rp_id: String,
    origin: String,
    timeout: Int,
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
    allow_credentials: List(BitArray),
  )
}

/// Returns default options (must provide rp_id, origin).
pub fn default_options() -> Options {
  Options(
    rp_id: "",
    origin: "",
    timeout: 60_000,
    user_verification: VerificationPreferred,
    user_presence: PresenceRequired,
    allow_cross_origin: False,
    allow_credentials: [],
  )
}

/// A finalized authentication challenge ready for verification.
pub opaque type Challenge {
  Challenge(
    bytes: BitArray,
    origin: String,
    rp_id: String,
    allowed_credentials: List(BitArray),
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
  )
}

/// Get the challenge bytes (for testing).
pub fn challenge_bytes(challenge: Challenge) -> BitArray {
  challenge.bytes
}

/// Get the origin (for testing).
pub fn challenge_origin(challenge: Challenge) -> String {
  challenge.origin
}

/// Get the RP ID (for testing).
pub fn challenge_rp_id(challenge: Challenge) -> String {
  challenge.rp_id
}

/// Parsed credential lookup info from response (for discoverable flow).
pub type ResponseInfo {
  ResponseInfo(credential_id: BitArray, user_handle: Option(BitArray))
}

/// Generate authentication options JSON and challenge verifier.
///
/// Returns a tuple of (options_json, challenge) where:
/// - `options_json` is the PublicKeyCredentialRequestOptionsJSON to send to browser
/// - `challenge` is the verifier to use with `verify()`
pub fn generate_options(options: Options) -> #(String, Challenge) {
  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let allow_credentials_json = case options.allow_credentials {
    [] -> []
    creds -> [
      #(
        "allowCredentials",
        json.array(creds, fn(cred_id) {
          json.object([
            #("id", json.string(bit_array.base64_url_encode(cred_id, False))),
            #("type", json.string("public-key")),
          ])
        }),
      ),
    ]
  }

  let options_json =
    json.object(
      [
        #("challenge", json.string(challenge_b64)),
        #("rpId", json.string(options.rp_id)),
        #("timeout", json.int(options.timeout)),
        #(
          "userVerification",
          json.string(user_verification_to_string(options.user_verification)),
        ),
      ]
      |> list.append(allow_credentials_json),
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: options.origin,
      rp_id: options.rp_id,
      allowed_credentials: options.allow_credentials,
      user_verification: options.user_verification,
      user_presence: options.user_presence,
      allow_cross_origin: options.allow_cross_origin,
    )

  #(json.to_string(options_json), challenge)
}

/// Parse response JSON to get credential_id/user_handle for lookup (discoverable flow).
///
/// Call this first, look up the stored credential, then call verify().
pub fn parse_response(
  response_json: String,
) -> Result(ResponseInfo, GlasskeysError) {
  use response <- result.try(parse_response_json(response_json))

  use credential_id <- result.try(decode_base64url(response.raw_id, "rawId"))

  use user_handle <- result.try(case response.user_handle {
    None -> Ok(None)
    Some(encoded) ->
      case bit_array.base64_url_decode(encoded) {
        Ok(decoded) -> Ok(Some(decoded))
        Error(_) ->
          Error(ParseError("Invalid base64url encoding for userHandle"))
      }
  })

  Ok(ResponseInfo(credential_id:, user_handle:))
}

/// Verify a SimpleWebAuthn AuthenticationResponseJSON.
///
/// Takes the JSON response string from the browser, the challenge from `generate_options()`,
/// and the stored credential to verify against.
///
/// For discoverable flow: call `parse_response()` first to get credential_id for lookup.
///
/// Returns an updated credential with the new sign count on success.
pub fn verify(
  response_json response_json: String,
  challenge challenge: Challenge,
  stored stored: Credential,
) -> Result(Credential, GlasskeysError) {
  // Parse the response JSON
  use response <- result.try(parse_response_json(response_json))

  // Decode base64url fields
  use credential_id <- result.try(decode_base64url(response.raw_id, "rawId"))
  use client_data_json <- result.try(decode_base64url(
    response.client_data_json,
    "clientDataJSON",
  ))
  use authenticator_data <- result.try(decode_base64url(
    response.authenticator_data,
    "authenticatorData",
  ))
  use signature <- result.try(decode_base64url(response.signature, "signature"))

  // Validate type field
  use <- bool.guard(
    when: response.credential_type != "public-key",
    return: Error(ParseError(
      "Invalid credential type: " <> response.credential_type,
    )),
  )

  // Check credential is allowed
  use <- bool.guard(
    when: !list.is_empty(challenge.allowed_credentials)
      && !list.contains(challenge.allowed_credentials, credential_id),
    return: Error(CredentialNotAllowed),
  )
  use <- bool.guard(
    when: credential_id != stored.id,
    return: Error(CredentialNotAllowed),
  )

  // Parse and verify client data
  use cd <- result.try(internal.parse_client_data(client_data_json))
  use <- bool.guard(
    when: cd.typ != "webauthn.get",
    return: Error(VerificationMismatch("type")),
  )
  use <- bool.guard(
    when: cd.challenge != challenge.bytes,
    return: Error(VerificationMismatch("challenge")),
  )
  use <- bool.guard(
    when: cd.origin != challenge.origin,
    return: Error(VerificationMismatch("origin")),
  )
  use <- bool.guard(
    when: cd.cross_origin && !challenge.allow_cross_origin,
    return: Error(VerificationMismatch("cross_origin")),
  )

  // Hash client data for signature verification
  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)

  // Parse authenticator data
  use auth_data <- result.try(internal.parse_authenticator_data(
    authenticator_data,
  ))

  // AT flag should not be set in authentication
  use <- bool.guard(
    when: option.is_some(auth_data.attested_credential),
    return: Error(ParseError("AT flag should not be set in authentication")),
  )

  // Verify RP ID hash
  let assert Ok(expected_rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(challenge.rp_id))
  use <- bool.guard(
    when: auth_data.rp_id_hash != expected_rp_id_hash,
    return: Error(VerificationMismatch("rp_id")),
  )

  // Verify user verification
  let verification_ok = case challenge.user_verification {
    VerificationRequired -> auth_data.user_verified
    _ -> True
  }
  use <- bool.guard(
    when: !verification_ok,
    return: Error(UserVerificationFailed),
  )

  // Verify user presence
  let presence_ok = case challenge.user_presence {
    PresenceRequired -> auth_data.user_present
    _ -> True
  }
  use <- bool.guard(when: !presence_ok, return: Error(UserPresenceFailed))

  // Verify signature
  let signed_data = bit_array.concat([authenticator_data, client_data_hash])
  use _ <- result.try(internal.verify_es256(
    stored.public_key,
    signed_data,
    signature,
  ))

  // Verify sign count (detect cloned authenticators)
  let sign_count_ok = case stored.sign_count, auth_data.sign_count {
    0, 0 -> True
    0, _ -> True
    _, 0 -> False
    _, _ -> auth_data.sign_count > stored.sign_count
  }
  use <- bool.guard(when: !sign_count_ok, return: Error(SignCountRegression))

  Ok(Credential(..stored, sign_count: auth_data.sign_count))
}

// Internal types and helpers

type ParsedResponse {
  ParsedResponse(
    id: String,
    raw_id: String,
    credential_type: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option(String),
  )
}

fn parse_response_json(
  json_string: String,
) -> Result(ParsedResponse, GlasskeysError) {
  // Main decoder for required fields
  let base_decoder = {
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use client_data_json <- decode.subfield(
      ["response", "clientDataJSON"],
      decode.string,
    )
    use authenticator_data <- decode.subfield(
      ["response", "authenticatorData"],
      decode.string,
    )
    use signature <- decode.subfield(["response", "signature"], decode.string)
    decode.success(#(
      id,
      raw_id,
      credential_type,
      client_data_json,
      authenticator_data,
      signature,
    ))
  }

  // userHandle is truly optional - may be missing entirely, null, or a string
  let user_handle_decoder =
    decode.one_of(
      decode.at(["response", "userHandle"], decode.optional(decode.string)),
      or: [decode.success(None)],
    )

  use
    #(
      id,
      raw_id,
      credential_type,
      client_data_json,
      authenticator_data,
      signature,
    )
  <- result.try(
    json.parse(json_string, base_decoder)
    |> result.map_error(fn(_) {
      ParseError("Invalid authentication response JSON")
    }),
  )

  let user_handle =
    json.parse(json_string, user_handle_decoder)
    |> result.unwrap(None)

  Ok(ParsedResponse(
    id:,
    raw_id:,
    credential_type:,
    client_data_json:,
    authenticator_data:,
    signature:,
    user_handle:,
  ))
}

fn decode_base64url(
  encoded: String,
  field_name: String,
) -> Result(BitArray, GlasskeysError) {
  bit_array.base64_url_decode(encoded)
  |> result.map_error(fn(_) {
    ParseError("Invalid base64url in " <> field_name)
  })
}

fn user_verification_to_string(uv: UserVerification) -> String {
  case uv {
    VerificationRequired -> "required"
    VerificationPreferred -> "preferred"
    VerificationDiscouraged -> "discouraged"
  }
}
