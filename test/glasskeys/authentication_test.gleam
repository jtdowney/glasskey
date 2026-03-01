import glasskeys.{
  Credential, CredentialNotAllowed, InvalidSignature, ParseError,
  SignCountRegression, UserVerificationFailed, VerificationMismatch,
  VerificationRequired,
}
import glasskeys/authentication
import glasskeys/testing.{AuthenticatorFlags}
import gleam/bit_array
import gleam/json
import gleam/option.{None, Some}
import kryptos/crypto
import kryptos/hash

pub fn generate_options_creates_valid_json_test() {
  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [<<1, 2, 3>>, <<4, 5, 6>>],
    )

  let #(options_json, challenge) = authentication.generate_options(options)

  // Verify options_json is not empty (it's JSON)
  assert options_json != ""

  // Verify challenge accessors work
  assert authentication.challenge_origin(challenge) == "https://example.com"
  assert authentication.challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(authentication.challenge_bytes(challenge)) == 32
}

pub fn verify_valid_authentication_test() {
  // First register a credential
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      credential: stored_credential,
      keypair: keypair,
      sign_count: 1,
    )
  let response_json = testing.to_authentication_json(response, credential_id)

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  let assert Ok(cred) = result
  assert cred.id == credential_id
  assert cred.sign_count == 1
  assert cred.public_key == public_key
}

pub fn verify_rejects_invalid_json_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)
  let invalid_json = "{not valid json"

  let result =
    authentication.verify(
      response_json: invalid_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(ParseError("Invalid authentication response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with wrong type in client data
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let wrong_type_client_data =
    testing.build_client_data(
      typ: "webauthn.create",
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )

  let assert Ok(client_data_hash) =
    crypto.hash(hash.Sha256, wrong_type_client_data)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(
              wrong_type_client_data,
              False,
            )),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(VerificationMismatch("type"))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with wrong challenge
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let wrong_challenge_client_data =
    testing.build_client_data_get(
      challenge: <<9, 9, 9, 9>>,
      origin: "https://example.com",
      cross_origin: False,
    )

  let assert Ok(client_data_hash) =
    crypto.hash(hash.Sha256, wrong_challenge_client_data)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(
              wrong_challenge_client_data,
              False,
            )),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(VerificationMismatch("challenge"))
}

pub fn verify_rejects_origin_mismatch_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with wrong origin
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let wrong_origin_client_data =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: "https://evil.com",
      cross_origin: False,
    )

  let assert Ok(client_data_hash) =
    crypto.hash(hash.Sha256, wrong_origin_client_data)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(
              wrong_origin_client_data,
              False,
            )),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(VerificationMismatch("origin"))
}

pub fn verify_rejects_credential_not_allowed_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let other_credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  // Create challenge that only allows a different credential
  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [other_credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      credential: stored_credential,
      keypair: keypair,
      sign_count: 1,
    )
  let response_json = testing.to_authentication_json(response, credential_id)

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(CredentialNotAllowed)
}

pub fn verify_rejects_credential_id_mismatch_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let different_credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [],
    )

  let #(_, challenge) = authentication.generate_options(options)
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      credential: stored_credential,
      keypair: keypair,
      sign_count: 1,
    )
  // Use different credential_id in the JSON than what's stored
  let response_json =
    testing.to_authentication_json(response, different_credential_id)

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(CredentialNotAllowed)
}

pub fn verify_rejects_invalid_signature_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with invalid signature
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: authentication.challenge_origin(challenge),
      cross_origin: False,
    )

  let invalid_signature = <<0:512>>

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(client_data_json, False)),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(invalid_signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(InvalidSignature)
}

pub fn verify_rejects_sign_count_regression_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  // Stored credential has sign_count of 10
  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 10)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Response has sign_count of 5 (regression)
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      credential: stored_credential,
      keypair: keypair,
      sign_count: 5,
    )
  let response_json = testing.to_authentication_json(response, credential_id)

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(SignCountRegression)
}

pub fn verify_rejects_sign_count_reset_to_zero_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  // Stored credential has sign_count of 10
  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 10)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Response has sign_count of 0 (suspicious reset)
  let response =
    testing.build_authentication_response(
      challenge: challenge,
      credential: stored_credential,
      keypair: keypair,
      sign_count: 0,
    )
  let response_json = testing.to_authentication_json(response, credential_id)

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(SignCountRegression)
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
      user_verification: VerificationRequired,
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with user_verified: False
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: authentication.challenge_origin(challenge),
      cross_origin: False,
    )

  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(client_data_json, False)),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(UserVerificationFailed)
}

pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
      user_verification: VerificationRequired,
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with user_verified: True
  let flags = AuthenticatorFlags(user_present: True, user_verified: True)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let client_data_json =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: authentication.challenge_origin(challenge),
      cross_origin: False,
    )

  let assert Ok(client_data_hash) = crypto.hash(hash.Sha256, client_data_json)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(client_data_json, False)),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  let assert Ok(cred) = result
  assert cred.id == credential_id
  assert cred.sign_count == 1
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let keypair = testing.generate_keypair()
  let credential_id = crypto.random_bytes(32)
  let public_key = testing.public_key(keypair)

  let stored_credential =
    Credential(id: credential_id, public_key: public_key, sign_count: 0)

  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: "example.com",
      origin: "https://example.com",
      allow_credentials: [credential_id],
      allow_cross_origin: False,
    )

  let #(_, challenge) = authentication.generate_options(options)

  // Build response with cross_origin: True
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)
  let auth_data =
    testing.build_authentication_authenticator_data(
      rp_id: authentication.challenge_rp_id(challenge),
      flags: flags,
      sign_count: 1,
    )

  let cross_origin_client_data =
    testing.build_client_data_get(
      challenge: authentication.challenge_bytes(challenge),
      origin: authentication.challenge_origin(challenge),
      cross_origin: True,
    )

  let assert Ok(client_data_hash) =
    crypto.hash(hash.Sha256, cross_origin_client_data)
  let signed_data = bit_array.concat([auth_data, client_data_hash])
  let signature = testing.sign(keypair, signed_data)

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #(
            "clientDataJSON",
            json.string(bit_array.base64_url_encode(
              cross_origin_client_data,
              False,
            )),
          ),
          #(
            "authenticatorData",
            json.string(bit_array.base64_url_encode(auth_data, False)),
          ),
          #(
            "signature",
            json.string(bit_array.base64_url_encode(signature, False)),
          ),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_credential,
    )

  assert result == Error(VerificationMismatch("cross_origin"))
}

pub fn parse_response_extracts_credential_info_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let user_handle = <<9, 10, 11, 12>>

  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #("clientDataJSON", json.string("dGVzdA")),
          #("authenticatorData", json.string("dGVzdA")),
          #("signature", json.string("dGVzdA")),
          #(
            "userHandle",
            json.string(bit_array.base64_url_encode(user_handle, False)),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == credential_id
  let assert Some(handle) = info.user_handle
  assert handle == user_handle
}

pub fn parse_response_handles_missing_user_handle_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  // Response with userHandle field entirely missing (not just null)
  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #("clientDataJSON", json.string("dGVzdA")),
          #("authenticatorData", json.string("dGVzdA")),
          #("signature", json.string("dGVzdA")),
          // No userHandle field at all
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == credential_id
  assert info.user_handle == None
}

pub fn parse_response_handles_null_user_handle_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  // Response with userHandle explicitly set to null
  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #("clientDataJSON", json.string("dGVzdA")),
          #("authenticatorData", json.string("dGVzdA")),
          #("signature", json.string("dGVzdA")),
          #("userHandle", json.null()),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let assert Ok(info) = authentication.parse_response(response_json)
  assert info.credential_id == credential_id
  assert info.user_handle == None
}

pub fn parse_response_errors_on_invalid_user_handle_base64_test() {
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

  // Response with invalid base64 in userHandle
  let response_json =
    json.object([
      #("id", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("rawId", json.string(bit_array.base64_url_encode(credential_id, False))),
      #("type", json.string("public-key")),
      #(
        "response",
        json.object([
          #("clientDataJSON", json.string("dGVzdA")),
          #("authenticatorData", json.string("dGVzdA")),
          #("signature", json.string("dGVzdA")),
          #("userHandle", json.string("!!!invalid-base64!!!")),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let assert Error(glasskeys.ParseError(msg)) =
    authentication.parse_response(response_json)
  assert msg == "Invalid base64url encoding for userHandle"
}
