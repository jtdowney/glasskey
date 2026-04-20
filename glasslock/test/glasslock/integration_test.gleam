import glasslock/authentication
import glasslock/registration
import glasslock/testing
import gleam/option

pub fn register_then_authenticate_es256_test() {
  let rp = registration.Rp(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")
  let keypair = testing.generate_es256_keypair()

  let #(_, reg_challenge) =
    registration.generate_options(
      registration.Options(
        ..registration.default_options(),
        rp:,
        user:,
        origin: "https://example.com",
        algorithms: [registration.Es256],
      ),
    )
  let reg_response =
    testing.build_registration_response_with_keypair(
      challenge: reg_challenge,
      keypair:,
    )
  let assert Ok(credential) =
    registration.verify(
      response_json: testing.to_registration_json(reg_response),
      challenge: reg_challenge,
    )
  assert credential.id == reg_response.credential_id
  assert credential.sign_count == 0

  let #(_, auth_challenge) =
    authentication.generate_options(
      authentication.Options(
        ..authentication.default_options(),
        rp_id: "example.com",
        origin: "https://example.com",
        allow_credentials: [credential.id],
      ),
    )
  let auth_response =
    testing.build_authentication_response(
      challenge: auth_challenge,
      keypair:,
      sign_count: 1,
    )
  let assert Ok(updated) =
    authentication.verify(
      response_json: testing.to_authentication_json(
        auth_response,
        credential_id: credential.id,
        user_handle: option.None,
      ),
      challenge: auth_challenge,
      stored: credential,
    )
  assert updated.sign_count == 1
}

pub fn register_then_authenticate_ed25519_test() {
  let rp = registration.Rp(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")
  let keypair = testing.generate_ed25519_keypair()

  let #(_, reg_challenge) =
    registration.generate_options(
      registration.Options(
        ..registration.default_options(),
        rp:,
        user:,
        origin: "https://example.com",
        algorithms: [registration.Ed25519],
      ),
    )
  let reg_response =
    testing.build_registration_response_with_keypair(
      challenge: reg_challenge,
      keypair:,
    )
  let assert Ok(credential) =
    registration.verify(
      response_json: testing.to_registration_json(reg_response),
      challenge: reg_challenge,
    )
  assert credential.id == reg_response.credential_id
  assert credential.sign_count == 0

  let #(_, auth_challenge) =
    authentication.generate_options(
      authentication.Options(
        ..authentication.default_options(),
        rp_id: "example.com",
        origin: "https://example.com",
        allow_credentials: [credential.id],
      ),
    )
  let auth_response =
    testing.build_authentication_response(
      challenge: auth_challenge,
      keypair:,
      sign_count: 1,
    )
  let assert Ok(updated) =
    authentication.verify(
      response_json: testing.to_authentication_json(
        auth_response,
        credential_id: credential.id,
        user_handle: option.None,
      ),
      challenge: auth_challenge,
      stored: credential,
    )
  assert updated.sign_count == 1
}

pub fn register_then_authenticate_rs256_test() {
  let rp = registration.Rp(id: "example.com", name: "Test App")
  let user =
    registration.User(id: <<1, 2, 3, 4>>, name: "test", display_name: "Test")
  let keypair = testing.generate_rs256_keypair()

  let #(_, reg_challenge) =
    registration.generate_options(
      registration.Options(
        ..registration.default_options(),
        rp:,
        user:,
        origin: "https://example.com",
        algorithms: [registration.Rs256],
      ),
    )
  let reg_response =
    testing.build_registration_response_with_keypair(
      challenge: reg_challenge,
      keypair:,
    )
  let assert Ok(credential) =
    registration.verify(
      response_json: testing.to_registration_json(reg_response),
      challenge: reg_challenge,
    )
  assert credential.id == reg_response.credential_id
  assert credential.sign_count == 0

  let #(_, auth_challenge) =
    authentication.generate_options(
      authentication.Options(
        ..authentication.default_options(),
        rp_id: "example.com",
        origin: "https://example.com",
        allow_credentials: [credential.id],
      ),
    )
  let auth_response =
    testing.build_authentication_response(
      challenge: auth_challenge,
      keypair:,
      sign_count: 1,
    )
  let assert Ok(updated) =
    authentication.verify(
      response_json: testing.to_authentication_json(
        auth_response,
        credential_id: credential.id,
        user_handle: option.None,
      ),
      challenge: auth_challenge,
      stored: credential,
    )
  assert updated.sign_count == 1
}
