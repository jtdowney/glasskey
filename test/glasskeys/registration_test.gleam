import glasskeys.{
  ParseError, UserVerificationFailed, VerificationMismatch, VerificationRequired,
}
import glasskeys/registration
import glasskeys/testing.{AuthenticatorFlags}
import gleam/bit_array
import gleam/json

pub fn generate_options_creates_valid_json_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(options_json, challenge) = registration.generate_options(options)

  // Verify options_json is not empty (it's JSON)
  assert options_json != ""

  // Verify challenge accessors work
  assert registration.challenge_origin(challenge) == "https://example.com"
  assert registration.challenge_rp_id(challenge) == "example.com"
  assert bit_array.byte_size(registration.challenge_bytes(challenge)) == 32
}

pub fn verify_valid_registration_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(_, challenge) = registration.generate_options(options)
  let response = testing.build_registration_response(challenge: challenge)
  let response_json = testing.to_registration_json(response)

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  let assert Ok(cred) = result
  assert cred.id == response.credential_id
  assert cred.sign_count == 0
  assert bit_array.byte_size(cred.public_key) == 65
}

pub fn verify_rejects_invalid_json_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(_, challenge) = registration.generate_options(options)
  let invalid_json = "{not valid json"

  let result =
    registration.verify(response_json: invalid_json, challenge: challenge)

  assert result == Error(ParseError("Invalid registration response JSON"))
}

pub fn verify_rejects_wrong_type_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(_, challenge) = registration.generate_options(options)

  // Build valid response but with wrong type in client data
  let response = testing.build_registration_response(challenge: challenge)
  let wrong_type_client_data =
    testing.build_client_data(
      typ: "webauthn.get",
      challenge: registration.challenge_bytes(challenge),
      origin: "https://example.com",
      cross_origin: False,
    )

  // Build JSON with wrong client data
  let response_json =
    json.object([
      #(
        "id",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
      #(
        "rawId",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
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
            "attestationObject",
            json.string(bit_array.base64_url_encode(
              response.attestation_object,
              False,
            )),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  assert result == Error(VerificationMismatch("type"))
}

pub fn verify_rejects_challenge_mismatch_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(_, challenge) = registration.generate_options(options)
  let response = testing.build_registration_response(challenge: challenge)

  // Build client data with wrong challenge
  let wrong_challenge_client_data =
    testing.build_client_data_create(
      challenge: <<9, 9, 9, 9>>,
      origin: "https://example.com",
      cross_origin: False,
    )

  let response_json =
    json.object([
      #(
        "id",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
      #(
        "rawId",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
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
            "attestationObject",
            json.string(bit_array.base64_url_encode(
              response.attestation_object,
              False,
            )),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  assert result == Error(VerificationMismatch("challenge"))
}

pub fn verify_rejects_origin_mismatch_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
    )

  let #(_, challenge) = registration.generate_options(options)
  let response = testing.build_registration_response(challenge: challenge)

  // Build client data with wrong origin
  let wrong_origin_client_data =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: "https://evil.com",
      cross_origin: False,
    )

  let response_json =
    json.object([
      #(
        "id",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
      #(
        "rawId",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
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
            "attestationObject",
            json.string(bit_array.base64_url_encode(
              response.attestation_object,
              False,
            )),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  assert result == Error(VerificationMismatch("origin"))
}

pub fn verify_rejects_when_verification_required_but_not_performed_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
      user_verification: VerificationRequired,
    )

  let #(_, challenge) = registration.generate_options(options)

  // Build response with user_verified: False
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
  let flags = AuthenticatorFlags(user_present: True, user_verified: False)

  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: registration.challenge_rp_id(challenge),
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: registration.challenge_origin(challenge),
      cross_origin: False,
    )

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
            "attestationObject",
            json.string(bit_array.base64_url_encode(attestation_object, False)),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  assert result == Error(UserVerificationFailed)
}

pub fn verify_succeeds_when_verification_required_and_performed_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
      user_verification: VerificationRequired,
    )

  let #(_, challenge) = registration.generate_options(options)

  // Build response with user_verified: True
  let keypair = testing.generate_keypair()
  let cose_key = testing.cose_key(keypair)
  let credential_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
  let flags = AuthenticatorFlags(user_present: True, user_verified: True)

  let auth_data =
    testing.build_registration_authenticator_data(
      rp_id: registration.challenge_rp_id(challenge),
      credential_id: credential_id,
      cose_key: cose_key,
      flags: flags,
      sign_count: 0,
    )

  let attestation_object = testing.build_attestation_object(auth_data)
  let client_data_json =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: registration.challenge_origin(challenge),
      cross_origin: False,
    )

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
            "attestationObject",
            json.string(bit_array.base64_url_encode(attestation_object, False)),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  let assert Ok(cred) = result
  assert cred.id == credential_id
  assert cred.sign_count == 0
}

pub fn verify_rejects_cross_origin_when_disabled_test() {
  let user_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let defaults = registration.default_options()
  let options =
    registration.Options(
      ..defaults,
      rp: registration.Rp(id: "example.com", name: "Test App"),
      user: registration.User(
        id: user_id,
        name: "testuser",
        display_name: "Test User",
      ),
      origin: "https://example.com",
      allow_cross_origin: False,
    )

  let #(_, challenge) = registration.generate_options(options)
  let response = testing.build_registration_response(challenge: challenge)

  // Build client data with cross_origin: True
  let cross_origin_client_data =
    testing.build_client_data_create(
      challenge: registration.challenge_bytes(challenge),
      origin: registration.challenge_origin(challenge),
      cross_origin: True,
    )

  let response_json =
    json.object([
      #(
        "id",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
      #(
        "rawId",
        json.string(bit_array.base64_url_encode(response.credential_id, False)),
      ),
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
            "attestationObject",
            json.string(bit_array.base64_url_encode(
              response.attestation_object,
              False,
            )),
          ),
        ]),
      ),
      #("clientExtensionResults", json.object([])),
    ])
    |> json.to_string

  let result =
    registration.verify(response_json: response_json, challenge: challenge)

  assert result == Error(VerificationMismatch("cross_origin"))
}
