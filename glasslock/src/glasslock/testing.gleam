//// Helpers for generating WebAuthn/FIDO2 test data in unit and
//// integration tests. Exposes high-level builders for common
//// scenarios and low-level building blocks for edge cases.
////
//// **This module is for testing only.** It should not be used in
//// production code.
////
//// Build a valid response, then use record update syntax to introduce the
//// flaw under test:
////
//// ```gleam
//// testing.to_registration_json(
////   testing.RegistrationResponse(..response, credential_type: "invalid-type"),
//// )
//// ```
////
//// Values the authenticator signs over — the credential ID and public key
//// inside `attestation_object`, and `authenticator_data` with its `signature`
//// — are not reachable this way; rebuild them with the lower-level builders.
////
//// ## Example
////
//// For a simple registration test:
////
//// ```gleam
//// import glasslock/registration
//// import glasslock/testing
////
//// pub fn registration_test() {
////   let #(_, challenge) =
////     registration.new(
////       relying_party: registration.RelyingParty(id: "example.com", name: "Test"),
////       user: registration.User(id: <<1, 2, 3>>, name: "test", display_name: "Test"),
////       origin: "https://example.com",
////     )
////     |> registration.build()
////
////   let response = testing.build_registration_response(challenge: challenge)
////   let response_json = testing.to_registration_json(response)
////
////   let assert Ok(credential) = registration.verify_json(response_json:, challenge:)
//// }
//// ```

import glasslock
import glasslock/authentication
import glasslock/internal
import glasslock/internal/cbor
import glasslock/registration
import gleam/bit_array
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/set
import gose
import gose/cose
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa

/// A COSE key pair for testing WebAuthn flows.
///
/// Construct with [`generate_es256_keypair`](#generate_es256_keypair),
/// [`generate_ed25519_keypair`](#generate_ed25519_keypair), or
/// [`generate_rs256_keypair`](#generate_rs256_keypair).
pub opaque type KeyPair {
  KeyPair(key: cose.Key, alg: gose.DigitalSignatureAlg)
}
/// Generate a new random ES256 (P-256) key pair.
pub fn generate_es256_keypair() -> KeyPair {
  let alg = gose.Ecdsa(gose.EcdsaP256)
  let key =
    gose.generate_ec(ec.P256)
    |> gose.with_alg(gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Generate a new random Ed25519 key pair.
pub fn generate_ed25519_keypair() -> KeyPair {
  let alg = gose.Eddsa
  let key =
    gose.generate_eddsa(eddsa.Ed25519)
    |> gose.with_alg(gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Generate a new random RS256 (RSA 2048-bit) key pair.
pub fn generate_rs256_keypair() -> KeyPair {
  let alg = gose.RsaPkcs1(gose.RsaPkcs1Sha256)
  let assert Ok(raw_key) = gose.generate_rsa(2048)
  let key = gose.with_alg(raw_key, gose.SigningAlg(gose.DigitalSignature(alg)))
  KeyPair(key:, alg:)
}

/// Get the public key in COSE CBOR format.
/// This is the format embedded in authenticator data during registration.
pub fn cose_key(keypair: KeyPair) -> BitArray {
  let assert Ok(pub_key) = gose.public_key(keypair.key)
  let assert Ok(cbor_bytes) = cose.key_to_cbor(pub_key)
  cbor_bytes
}

/// Get the public key as a parsed `glasslock.PublicKey`.
/// Use to construct a stored `Credential` in tests.
pub fn public_key(keypair: KeyPair) -> glasslock.PublicKey {
  glasslock.PublicKey(cose_key(keypair))
}

/// Sign a message using the algorithm stamped on the keypair.
///
/// Dispatches to ECDSA, EdDSA, RSA PKCS#1 v1.5, or RSA PSS based on the COSE
/// alg label assigned when the keypair was generated. Returns the wire-format
/// signature bytes a real WebAuthn authenticator would produce: ASN.1 DER for
/// ECDSA, raw for EdDSA, and raw PKCS#1 v1.5 or PSS bytes for RSA.
pub fn sign(keypair keypair: KeyPair, message message: BitArray) -> BitArray {
  let assert Ok(private_der) = gose.to_der(keypair.key)
  case keypair.alg {
    gose.Ecdsa(_) -> {
      let assert Ok(#(private, _)) = ec.from_der(private_der)
      ecdsa.sign(private, message, hash.Sha256)
    }
    gose.Eddsa -> {
      let assert Ok(#(private, _)) = eddsa.from_der(private_der)
      eddsa.sign(private, message)
    }
    gose.RsaPkcs1(_) -> {
      let assert Ok(#(private, _)) = rsa.from_der(private_der, rsa.Pkcs8)
      rsa.sign(private, message, hash.Sha256, rsa.Pkcs1v15)
    }
    gose.RsaPss(_) -> {
      let assert Ok(#(private, _)) = rsa.from_der(private_der, rsa.Pkcs8)
      rsa.sign(private, message, hash.Sha256, rsa.Pss(rsa.SaltLengthHashLen))
    }
  }
}

/// Authenticator flags for building authenticator data.
pub type AuthenticatorFlags {
  AuthenticatorFlags(
    /// WebAuthn UP (user presence) flag: the user touched or interacted
    /// with the authenticator.
    user_present: Bool,
    /// WebAuthn UV (user verification) flag: the authenticator performed
    /// biometric or PIN verification.
    user_verified: Bool,
  )
}

/// User present, not user verified.
pub const default_flags = AuthenticatorFlags(
  user_present: True,
  user_verified: False,
)

fn encode_flags(
  flags: AuthenticatorFlags,
  has_attested_credential has_attested_credential: Bool,
) -> Int {
  let up = case flags.user_present {
    True -> 0x01
    False -> 0
  }
  let uv = case flags.user_verified {
    True -> 0x04
    False -> 0
  }
  let at = case has_attested_credential {
    True -> 0x40
    False -> 0
  }
  up
  |> int.bitwise_or(uv)
  |> int.bitwise_or(at)
}

/// Build client data JSON with a caller-supplied type field.
///
/// Parameters allow constructing invalid data for error testing:
/// - Use a different `origin` to test origin mismatch
/// - Use a different `challenge` to test challenge mismatch
/// - Set `cross_origin: True` with a challenge that disallows it
pub fn build_client_data(
  type_ type_: String,
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
  top_origin top_origin: Option(String),
) -> BitArray {
  let challenge_b64 = bit_array.base64_url_encode(challenge, False)
  let base_fields = [
    #("type", json.string(type_)),
    #("challenge", json.string(challenge_b64)),
    #("origin", json.string(origin)),
    #("crossOrigin", json.bool(cross_origin)),
  ]
  let fields = case top_origin {
    option.Some(top) -> [#("topOrigin", json.string(top)), ..base_fields]
    option.None -> base_fields
  }
  json.object(fields)
  |> json.to_string
  |> bit_array.from_string
}

/// Build `webauthn.create` client data JSON for registration.
pub fn build_client_data_create(
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  build_client_data(
    type_: "webauthn.create",
    challenge:,
    origin:,
    cross_origin:,
    top_origin: option.None,
  )
}

/// Build `webauthn.get` client data JSON for authentication.
pub fn build_client_data_get(
  challenge challenge: BitArray,
  origin origin: String,
  cross_origin cross_origin: Bool,
) -> BitArray {
  build_client_data(
    type_: "webauthn.get",
    challenge:,
    origin:,
    cross_origin:,
    top_origin: option.None,
  )
}

/// Complete response data for a registration ceremony.
pub type RegistrationResponse {
  RegistrationResponse(
    /// Emitted as `id`. Base64url of `credential_id` in a real response.
    id: String,
    /// Emitted as `rawId`. Matches the attested credential ID inside
    /// `attestation_object` in a real response.
    credential_id: BitArray,
    /// Emitted as `type`. `"public-key"` for a real credential.
    credential_type: String,
    /// UTF-8 encoded client data JSON.
    client_data_json: BitArray,
    /// CBOR-encoded attestation object.
    attestation_object: BitArray,
    /// Omitted from the envelope when empty.
    transports: List(glasslock.Transport),
  )
}

/// Build authenticator data for registration (includes attested credential).
/// Pass `cose_key(keypair)` for the `cose_key_cbor` parameter.
pub fn build_registration_authenticator_data(
  relying_party_id relying_party_id: String,
  credential_id credential_id: BitArray,
  cose_key_cbor cose_key_cbor: BitArray,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(relying_party_id))
  let flags_byte = encode_flags(flags, has_attested_credential: True)
  let aaguid = <<0:128>>
  let cred_id_len = bit_array.byte_size(credential_id)

  bit_array.concat([
    rp_id_hash,
    <<flags_byte>>,
    <<sign_count:size(32)>>,
    aaguid,
    <<cred_id_len:size(16)>>,
    credential_id,
    cose_key_cbor,
  ])
}

/// Build an attestation object. glasslock accepts only `"none"` with an
/// empty statement.
pub fn build_attestation_object(
  format format: String,
  authenticator_data authenticator_data: BitArray,
  attestation_statement attestation_statement: List(#(String, Int)),
) -> BitArray {
  let entries =
    list.map(attestation_statement, fn(entry) {
      #(cbor.String(entry.0), cbor.Int(entry.1))
    })

  cbor.encode(
    cbor.Map([
      #(cbor.String("fmt"), cbor.String(format)),
      #(cbor.String("authData"), cbor.Bytes(authenticator_data)),
      #(cbor.String("attStmt"), cbor.Map(entries)),
    ]),
  )
}

/// Build a complete registration response for the given challenge.
///
/// Generates a fresh ES256 keypair and credential ID. The generated keypair is
/// not part of the returned response; use
/// [`build_registration_response_with_keypair`](#build_registration_response_with_keypair)
/// to supply a keypair of a different algorithm, or to keep the keypair for a
/// follow-on authentication response.
pub fn build_registration_response(
  challenge challenge: registration.Challenge,
) -> RegistrationResponse {
  build_registration_response_with_keypair(
    challenge:,
    keypair: generate_es256_keypair(),
  )
}

/// Build a complete registration response using a caller-supplied keypair.
///
/// Useful when the test needs to exercise an algorithm other than ES256. The
/// keypair determines the COSE algorithm embedded in the attested credential.
pub fn build_registration_response_with_keypair(
  challenge challenge: registration.Challenge,
  keypair keypair: KeyPair,
) -> RegistrationResponse {
  let data = registration.challenge_data(challenge)
  let assert Ok(origin) = list.first(set.to_list(data.origins))
  let credential_id = crypto.random_bytes(16)
  let authenticator_data =
    build_registration_authenticator_data(
      relying_party_id: data.rp_id,
      credential_id:,
      cose_key_cbor: cose_key(keypair),
      flags: default_flags,
      sign_count: 0,
    )
  let client_data_json =
    build_client_data_create(
      challenge: data.bytes,
      origin:,
      cross_origin: False,
    )
  RegistrationResponse(
    id: bit_array.base64_url_encode(credential_id, False),
    credential_id:,
    credential_type: "public-key",
    client_data_json:,
    attestation_object: build_attestation_object(
      format: "none",
      authenticator_data:,
      attestation_statement: [],
    ),
    transports: [],
  )
}

fn base64url_json(bytes: BitArray) -> Json {
  json.string(bit_array.base64_url_encode(bytes, False))
}

/// Convert a registration response to a `RegistrationResponseJSON` string.
pub fn to_registration_json(response: RegistrationResponse) -> String {
  let response_fields = [
    #("clientDataJSON", base64url_json(response.client_data_json)),
    #("attestationObject", base64url_json(response.attestation_object)),
  ]
  let response_fields = case response.transports {
    [] -> response_fields
    transports -> [
      #(
        "transports",
        json.array(transports, fn(transport) {
          transport
          |> internal.transport_to_string
          |> json.string
        }),
      ),
      ..response_fields
    ]
  }

  json.object([
    #("id", json.string(response.id)),
    #("rawId", base64url_json(response.credential_id)),
    #("type", json.string(response.credential_type)),
    #("response", json.object(response_fields)),
    #("clientExtensionResults", json.object([])),
  ])
  |> json.to_string
}

/// Complete response data for an authentication ceremony.
pub type AuthenticationResponse {
  AuthenticationResponse(
    /// Emitted as `id`. Base64url of `credential_id` in a real response.
    id: String,
    /// Emitted as `rawId`.
    credential_id: BitArray,
    /// Emitted as `type`. `"public-key"` for a real credential.
    credential_type: String,
    authenticator_data: BitArray,
    /// UTF-8 encoded client data JSON.
    client_data_json: BitArray,
    /// Signature over `authenticator_data || SHA-256(client_data_json)`.
    signature: BitArray,
    user_handle: Option(BitArray),
  )
}

/// Build authenticator data for authentication (no attested credential).
pub fn build_authentication_authenticator_data(
  relying_party_id relying_party_id: String,
  flags flags: AuthenticatorFlags,
  sign_count sign_count: Int,
) -> BitArray {
  let assert Ok(rp_id_hash) =
    crypto.hash(hash.Sha256, bit_array.from_string(relying_party_id))
  let flags_byte = encode_flags(flags, has_attested_credential: False)

  bit_array.concat([rp_id_hash, <<flags_byte>>, <<sign_count:size(32)>>])
}

/// Sign an authentication message the same way a real authenticator would:
/// ECDSA/EdDSA/RSA over `authenticator_data || SHA-256(client_data_json)`.
pub fn sign_authentication_message(
  keypair keypair: KeyPair,
  authenticator_data authenticator_data: BitArray,
  client_data_json client_data_json: BitArray,
) -> BitArray {
  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)
  sign(
    keypair:,
    message: bit_array.concat([authenticator_data, client_data_hash]),
  )
}

/// Build a complete authentication response for the given challenge.
///
/// Uses the keypair to generate a valid signature.
pub fn build_authentication_response(
  challenge challenge: authentication.Challenge,
  credential_id credential_id: BitArray,
  keypair keypair: KeyPair,
  sign_count sign_count: Int,
) -> AuthenticationResponse {
  let data = authentication.challenge_data(challenge)
  let assert Ok(origin) = list.first(set.to_list(data.origins))
  let authenticator_data =
    build_authentication_authenticator_data(
      relying_party_id: data.rp_id,
      flags: default_flags,
      sign_count: sign_count,
    )

  let client_data_json =
    build_client_data_get(challenge: data.bytes, origin:, cross_origin: False)

  let signature =
    sign_authentication_message(
      keypair:,
      authenticator_data:,
      client_data_json:,
    )

  AuthenticationResponse(
    id: bit_array.base64_url_encode(credential_id, False),
    credential_id:,
    credential_type: "public-key",
    authenticator_data:,
    client_data_json:,
    signature:,
    user_handle: option.None,
  )
}

/// Convert an authentication response to an `AuthenticationResponseJSON` string.
pub fn to_authentication_json(response: AuthenticationResponse) -> String {
  let user_handle_json = case response.user_handle {
    option.Some(handle) -> base64url_json(handle)
    option.None -> json.null()
  }

  json.object([
    #("id", json.string(response.id)),
    #("rawId", base64url_json(response.credential_id)),
    #("type", json.string(response.credential_type)),
    #(
      "response",
      json.object([
        #("clientDataJSON", base64url_json(response.client_data_json)),
        #("authenticatorData", base64url_json(response.authenticator_data)),
        #("signature", base64url_json(response.signature)),
        #("userHandle", user_handle_json),
      ]),
    ),
    #("clientExtensionResults", json.object([])),
  ])
  |> json.to_string
}
