//// WebAuthn registration API compatible with SimpleWebAuthn browser.
////
//// ## Example
////
//// ```gleam
//// import glasskeys/registration
////
//// // Generate options for browser
//// let #(options_json, challenge) = registration.generate_options(
//// registration.Options(
////     rp: registration.Rp(id: "example.com", name: "My App"),
////     user: registration.User(id: user_id, name: "john", display_name: "John"),
////     origin: "https://example.com",
////     ..registration.default_options()
////   ),
//// )
////
//// // Send options_json to browser, receive response_json back
////
//// // Verify the response
//// case registration.verify(response_json, challenge) {
////   Ok(credential) -> // Store credential
////   Error(e) -> // Handle error
//// }
//// ```

import glasskeys.{
  type Credential, type GlasskeysError, type UserPresence, type UserVerification,
  Credential, ParseError, PresenceRequired, UserPresenceFailed,
  UserVerificationFailed, VerificationDiscouraged, VerificationMismatch,
  VerificationPreferred, VerificationRequired,
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

/// Relying party information.
pub type Rp {
  Rp(id: String, name: String)
}

/// User information for registration.
pub type User {
  User(id: BitArray, name: String, display_name: String)
}

/// Attestation conveyance preference.
pub type Attestation {
  AttestationNone
  AttestationIndirect
  AttestationDirect
  AttestationEnterprise
}

/// Authenticator attachment preference.
pub type AuthenticatorAttachment {
  Platform
  CrossPlatform
}

/// Resident key (discoverable credential) requirement.
pub type ResidentKey {
  ResidentKeyDiscouraged
  ResidentKeyPreferred
  ResidentKeyRequired
}

/// Supported cryptographic algorithms.
pub type Algorithm {
  Es256
}

/// Options for registration challenge generation.
pub type Options {
  Options(
    rp: Rp,
    user: User,
    origin: String,
    timeout: Int,
    attestation: Attestation,
    authenticator_attachment: Option(AuthenticatorAttachment),
    resident_key: ResidentKey,
    user_verification: UserVerification,
    user_presence: UserPresence,
    allow_cross_origin: Bool,
    algorithms: List(Algorithm),
    exclude_credentials: List(BitArray),
  )
}

/// Returns default options (must provide rp, user, origin).
pub fn default_options() -> Options {
  Options(
    rp: Rp(id: "", name: ""),
    user: User(id: <<>>, name: "", display_name: ""),
    origin: "",
    timeout: 60_000,
    attestation: AttestationNone,
    authenticator_attachment: None,
    resident_key: ResidentKeyPreferred,
    user_verification: VerificationPreferred,
    user_presence: PresenceRequired,
    allow_cross_origin: False,
    algorithms: [Es256],
    exclude_credentials: [],
  )
}

/// A finalized registration challenge ready for verification.
pub opaque type Challenge {
  Challenge(
    bytes: BitArray,
    origin: String,
    rp_id: String,
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

/// Generate registration options JSON and challenge verifier.
///
/// Returns a tuple of (options_json, challenge) where:
/// - `options_json` is the PublicKeyCredentialCreationOptionsJSON to send to browser
/// - `challenge` is the verifier to use with `verify()`
pub fn generate_options(options: Options) -> #(String, Challenge) {
  let challenge_bytes = crypto.random_bytes(32)
  let challenge_b64 = bit_array.base64_url_encode(challenge_bytes, False)

  let user_id_b64 = bit_array.base64_url_encode(options.user.id, False)

  let pub_key_params =
    list.map(options.algorithms, fn(alg) {
      json.object([
        #("type", json.string("public-key")),
        #("alg", json.int(algorithm_to_cose(alg))),
      ])
    })

  let authenticator_selection =
    json.object(
      [
        #(
          "residentKey",
          json.string(resident_key_to_string(options.resident_key)),
        ),
        #(
          "userVerification",
          json.string(user_verification_to_string(options.user_verification)),
        ),
      ]
      |> maybe_add_attachment(options.authenticator_attachment),
    )

  let exclude_credentials_json = case options.exclude_credentials {
    [] -> []
    creds -> [
      #(
        "excludeCredentials",
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
        #(
          "rp",
          json.object([
            #("id", json.string(options.rp.id)),
            #("name", json.string(options.rp.name)),
          ]),
        ),
        #(
          "user",
          json.object([
            #("id", json.string(user_id_b64)),
            #("name", json.string(options.user.name)),
            #("displayName", json.string(options.user.display_name)),
          ]),
        ),
        #("pubKeyCredParams", json.preprocessed_array(pub_key_params)),
        #("timeout", json.int(options.timeout)),
        #(
          "attestation",
          json.string(attestation_to_string(options.attestation)),
        ),
        #("authenticatorSelection", authenticator_selection),
      ]
      |> list.append(exclude_credentials_json),
    )

  let challenge =
    Challenge(
      bytes: challenge_bytes,
      origin: options.origin,
      rp_id: options.rp.id,
      user_verification: options.user_verification,
      user_presence: options.user_presence,
      allow_cross_origin: options.allow_cross_origin,
    )

  #(json.to_string(options_json), challenge)
}

/// Verify a SimpleWebAuthn RegistrationResponseJSON.
///
/// Takes the JSON response string from the browser and the challenge from `generate_options()`.
/// Returns the verified credential on success.
pub fn verify(
  response_json response_json: String,
  challenge challenge: Challenge,
) -> Result(Credential, GlasskeysError) {
  // Parse the response JSON
  use response <- result.try(parse_response_json(response_json))

  // Decode base64url fields
  use client_data_json <- result.try(decode_base64url(
    response.client_data_json,
    "clientDataJSON",
  ))
  use attestation_object <- result.try(decode_base64url(
    response.attestation_object,
    "attestationObject",
  ))

  // Validate type field
  use <- bool.guard(
    when: response.credential_type != "public-key",
    return: Error(ParseError(
      "Invalid credential type: " <> response.credential_type,
    )),
  )

  // Parse and verify client data
  use cd <- result.try(internal.parse_client_data(client_data_json))
  use <- bool.guard(
    when: cd.typ != "webauthn.create",
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

  // Parse attestation object
  use attestation_obj <- result.try(internal.parse_attestation_object(
    attestation_object,
  ))
  use #(auth_data_bytes, att_stmt, fmt) <- result.try(
    internal.extract_attestation_fields(attestation_obj),
  )
  use auth_data <- result.try(internal.parse_authenticator_data(auth_data_bytes))

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

  // Extract attested credential
  use attested <- result.try(case auth_data.attested_credential {
    Some(cred) -> Ok(cred)
    None -> Error(ParseError("No attested credential in registration"))
  })

  // Parse public key
  use cose_key <- result.try(internal.parse_public_key(attested.public_key_cbor))
  let public_key = internal.cose_to_uncompressed_point(cose_key)

  // Verify attestation
  use _ <- result.try(internal.verify_attestation(fmt, att_stmt))

  Ok(Credential(
    id: attested.credential_id,
    public_key: public_key,
    sign_count: auth_data.sign_count,
  ))
}

// Internal types and helpers

type ParsedResponse {
  ParsedResponse(
    id: String,
    raw_id: String,
    credential_type: String,
    client_data_json: String,
    attestation_object: String,
  )
}

fn parse_response_json(
  json_string: String,
) -> Result(ParsedResponse, GlasskeysError) {
  let decoder = {
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use client_data_json <- decode.subfield(
      ["response", "clientDataJSON"],
      decode.string,
    )
    use attestation_object <- decode.subfield(
      ["response", "attestationObject"],
      decode.string,
    )
    decode.success(ParsedResponse(
      id:,
      raw_id:,
      credential_type:,
      client_data_json:,
      attestation_object:,
    ))
  }

  json.parse(json_string, decoder)
  |> result.map_error(fn(_) { ParseError("Invalid registration response JSON") })
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

fn algorithm_to_cose(alg: Algorithm) -> Int {
  case alg {
    Es256 -> -7
  }
}

fn attestation_to_string(att: Attestation) -> String {
  case att {
    AttestationNone -> "none"
    AttestationIndirect -> "indirect"
    AttestationDirect -> "direct"
    AttestationEnterprise -> "enterprise"
  }
}

fn resident_key_to_string(rk: ResidentKey) -> String {
  case rk {
    ResidentKeyDiscouraged -> "discouraged"
    ResidentKeyPreferred -> "preferred"
    ResidentKeyRequired -> "required"
  }
}

fn user_verification_to_string(uv: UserVerification) -> String {
  case uv {
    VerificationRequired -> "required"
    VerificationPreferred -> "preferred"
    VerificationDiscouraged -> "discouraged"
  }
}

fn maybe_add_attachment(
  fields: List(#(String, json.Json)),
  attachment: Option(AuthenticatorAttachment),
) -> List(#(String, json.Json)) {
  case attachment {
    None -> fields
    Some(Platform) ->
      list.append(fields, [
        #("authenticatorAttachment", json.string("platform")),
      ])
    Some(CrossPlatform) ->
      list.append(fields, [
        #("authenticatorAttachment", json.string("cross-platform")),
      ])
  }
}
