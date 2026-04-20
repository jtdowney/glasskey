import glasskey
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import qcheck
import unitest

pub fn main() {
  unitest.main()
}

fn to_dynamic(json_string: String) -> Dynamic {
  let assert Ok(value) = json.parse(json_string, decode.dynamic)
  value
}

type RegistrationFixture {
  RegistrationFixture(
    challenge: String,
    rp_id: String,
    rp_name: String,
    user_id: String,
    user_name: String,
    user_display_name: String,
    algorithms: List(Int),
    timeout: option.Option(Int),
    attestation: String,
    resident_key: String,
    user_verification: String,
    authenticator_attachment: option.Option(String),
    exclude_credentials: List(String),
  )
}

fn default_registration_fixture() -> RegistrationFixture {
  RegistrationFixture(
    challenge: "dGVzdA",
    rp_id: "example.com",
    rp_name: "App",
    user_id: "dQ",
    user_name: "u",
    user_display_name: "U",
    algorithms: [-7],
    timeout: option.None,
    attestation: "none",
    resident_key: "preferred",
    user_verification: "preferred",
    authenticator_attachment: option.None,
    exclude_credentials: [],
  )
}

fn build_registration_options(fixture: RegistrationFixture) -> String {
  let auth_selection_fields = [
    #("residentKey", json.string(fixture.resident_key)),
    #("userVerification", json.string(fixture.user_verification)),
  ]
  let auth_selection_fields = case fixture.authenticator_attachment {
    option.Some(value) -> [
      #("authenticatorAttachment", json.string(value)),
      ..auth_selection_fields
    ]
    option.None -> auth_selection_fields
  }

  let pub_key_cred_params =
    json.preprocessed_array(
      list.map(fixture.algorithms, fn(alg) {
        json.object([
          #("type", json.string("public-key")),
          #("alg", json.int(alg)),
        ])
      }),
    )

  let fields = [
    #("challenge", json.string(fixture.challenge)),
    #(
      "rp",
      json.object([
        #("id", json.string(fixture.rp_id)),
        #("name", json.string(fixture.rp_name)),
      ]),
    ),
    #(
      "user",
      json.object([
        #("id", json.string(fixture.user_id)),
        #("name", json.string(fixture.user_name)),
        #("displayName", json.string(fixture.user_display_name)),
      ]),
    ),
    #("pubKeyCredParams", pub_key_cred_params),
    #("attestation", json.string(fixture.attestation)),
    #("authenticatorSelection", json.object(auth_selection_fields)),
  ]

  let fields = case fixture.timeout {
    option.Some(t) -> [#("timeout", json.int(t)), ..fields]
    option.None -> fields
  }

  let fields = case fixture.exclude_credentials {
    [] -> fields
    ids -> [
      #(
        "excludeCredentials",
        json.preprocessed_array(
          list.map(ids, fn(id) {
            json.object([
              #("id", json.string(id)),
              #("type", json.string("public-key")),
            ])
          }),
        ),
      ),
      ..fields
    ]
  }

  json.object(fields) |> json.to_string
}

pub fn decode_registration_options_test() {
  let json =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        challenge: "dGVzdC1jaGFsbGVuZ2U",
        rp_name: "My App",
        user_id: "dXNlci0x",
        user_name: "john",
        user_display_name: "John",
        timeout: option.Some(60_000),
      ),
    )

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())

  assert opt.challenge == <<"test-challenge":utf8>>
  assert opt.rp_id == "example.com"
  assert opt.rp_name == "My App"
  assert opt.user_id == <<"user-1":utf8>>
  assert opt.user_name == "john"
  assert opt.user_display_name == "John"
  assert opt.algorithms == [glasskey.Es256]
  assert opt.timeout == option.Some(60_000)
  assert opt.attestation == glasskey.AttestationNone
  assert opt.resident_key == glasskey.Preferred
  assert opt.user_verification == glasskey.Preferred
  assert opt.authenticator_attachment == option.None
  assert opt.exclude_credentials == []
}

pub fn decode_registration_options_with_all_algorithms_test() {
  let json =
    build_registration_options(
      RegistrationFixture(..default_registration_fixture(), algorithms: [
        -7,
        -8,
        -257,
      ]),
    )

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())
  assert opt.algorithms == [glasskey.Es256, glasskey.Ed25519, glasskey.Rs256]
}

pub fn decode_registration_options_with_exclude_credentials_test() {
  let json =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        exclude_credentials: ["AQID"],
      ),
    )

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())

  assert opt.exclude_credentials == [<<1, 2, 3>>]
}

pub fn decode_registration_options_requirement_variants_test() {
  let variants = [
    #("required", glasskey.Required),
    #("preferred", glasskey.Preferred),
    #("discouraged", glasskey.Discouraged),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let json =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          resident_key: string,
        ),
      )
    let assert Ok(opt) =
      decode.run(to_dynamic(json), glasskey.registration_options_decoder())
    assert opt.resident_key == expected
  })
}

pub fn decode_registration_options_attestation_variants_test() {
  let variants = [
    #("none", glasskey.AttestationNone),
    #("indirect", glasskey.AttestationIndirect),
    #("direct", glasskey.AttestationDirect),
    #("enterprise", glasskey.AttestationEnterprise),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let json_str =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          attestation: string,
        ),
      )
    let assert Ok(opt) =
      decode.run(to_dynamic(json_str), glasskey.registration_options_decoder())
    assert opt.attestation == expected
  })
}

pub fn decode_registration_options_authenticator_attachment_variants_test() {
  let variants = [
    #("platform", option.Some(glasskey.Platform)),
    #("cross-platform", option.Some(glasskey.CrossPlatform)),
  ]

  list.each(variants, fn(pair) {
    let #(string, expected) = pair
    let json_str =
      build_registration_options(
        RegistrationFixture(
          ..default_registration_fixture(),
          authenticator_attachment: option.Some(string),
        ),
      )
    let assert Ok(opt) =
      decode.run(to_dynamic(json_str), glasskey.registration_options_decoder())
    assert opt.authenticator_attachment == expected
  })
}

pub fn decode_registration_options_missing_required_fields_test() {
  let assert Error(_) =
    decode.run(to_dynamic("{}"), glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_requirement_test() {
  let json =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        resident_key: "typo-required",
      ),
    )

  let assert Error(_) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_algorithm_test() {
  let json =
    build_registration_options(
      RegistrationFixture(..default_registration_fixture(), algorithms: [-999]),
    )

  let assert Error(_) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_attestation_test() {
  let json =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        attestation: "bogus-format",
      ),
    )

  let assert Error(_) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())
}

pub fn decode_registration_options_unknown_authenticator_attachment_test() {
  let json =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        authenticator_attachment: option.Some("bogus-attachment"),
      ),
    )

  let assert Error(_) =
    decode.run(to_dynamic(json), glasskey.registration_options_decoder())
}

pub fn decode_authentication_options_test() {
  let json =
    json.object([
      #("challenge", json.string("dGVzdC1jaGFsbGVuZ2U")),
      #("rpId", json.string("example.com")),
      #("timeout", json.int(60_000)),
      #("userVerification", json.string("preferred")),
    ])
    |> json.to_string

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.authentication_options_decoder())

  assert opt.challenge == <<"test-challenge":utf8>>
  assert opt.rp_id == option.Some("example.com")
  assert opt.timeout == option.Some(60_000)
  assert opt.user_verification == glasskey.Preferred
  assert opt.allow_credentials == []
}

pub fn decode_authentication_options_with_allow_credentials_test() {
  let json =
    json.object([
      #("challenge", json.string("dGVzdA")),
      #("rpId", json.string("example.com")),
      #("timeout", json.int(60_000)),
      #("userVerification", json.string("required")),
      #(
        "allowCredentials",
        json.preprocessed_array([
          json.object([
            #("id", json.string("AQID")),
            #("type", json.string("public-key")),
          ]),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.authentication_options_decoder())

  assert opt.allow_credentials == [<<1, 2, 3>>]
  assert opt.user_verification == glasskey.Required
}

pub fn decode_authentication_options_minimal_test() {
  let json =
    json.object([#("challenge", json.string("dGVzdA"))])
    |> json.to_string

  let assert Ok(opt) =
    decode.run(to_dynamic(json), glasskey.authentication_options_decoder())

  assert opt.challenge == <<"test":utf8>>
  assert opt.rp_id == option.None
  assert opt.timeout == option.None
  assert opt.user_verification == glasskey.Preferred
  assert opt.allow_credentials == []
}

pub fn decode_authentication_options_missing_required_fields_test() {
  let assert Error(_) =
    decode.run(to_dynamic("{}"), glasskey.authentication_options_decoder())
}

pub fn decode_authentication_options_unknown_user_verification_test() {
  let json =
    json.object([
      #("challenge", json.string("dGVzdA")),
      #("userVerification", json.string("bogus-value")),
    ])
    |> json.to_string
  let assert Error(_) =
    decode.run(to_dynamic(json), glasskey.authentication_options_decoder())
}

pub fn encode_registration_response_test() {
  let result =
    glasskey.encode_registration_response(
      glasskey.RegistrationCredential(
        id: "cred-123",
        raw_id: <<1, 2, 3>>,
        client_data_json: <<4, 5, 6>>,
        attestation_object: <<7, 8, 9>>,
      ),
    )

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
    decode.success(#(
      id,
      raw_id,
      credential_type,
      client_data_json,
      attestation_object,
    ))
  }

  let assert Ok(#(id, raw_id, credential_type, cdj, ao)) =
    json.parse(result, decoder)

  assert id == "cred-123"
  assert raw_id == "AQID"
  assert credential_type == "public-key"
  assert cdj == "BAUG"
  assert ao == "BwgJ"
}

pub fn encode_authentication_response_with_user_handle_test() {
  let result =
    glasskey.encode_authentication_response(glasskey.AuthenticationCredential(
      id: "cred-abc",
      raw_id: <<10, 20, 30>>,
      client_data_json: <<40, 50, 60>>,
      authenticator_data: <<70, 80, 90>>,
      signature: <<100, 110, 120>>,
      user_handle: option.Some(<<1, 2>>),
    ))

  let decoder = {
    use id <- decode.field("id", decode.string)
    use credential_type <- decode.field("type", decode.string)
    use authenticator_data <- decode.subfield(
      ["response", "authenticatorData"],
      decode.string,
    )
    use signature <- decode.subfield(["response", "signature"], decode.string)
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(#(
      id,
      credential_type,
      authenticator_data,
      signature,
      user_handle,
    ))
  }

  let assert Ok(#(id, credential_type, ad, sig, uh)) =
    json.parse(result, decoder)

  assert id == "cred-abc"
  assert credential_type == "public-key"
  assert ad == "RlBa"
  assert sig == "ZG54"
  assert uh == option.Some("AQI")
}

pub fn encode_authentication_response_null_user_handle_test() {
  let result =
    glasskey.encode_authentication_response(glasskey.AuthenticationCredential(
      id: "cred-x",
      raw_id: <<1>>,
      client_data_json: <<2>>,
      authenticator_data: <<3>>,
      signature: <<4>>,
      user_handle: option.None,
    ))

  let decoder = {
    use user_handle <- decode.subfield(
      ["response", "userHandle"],
      decode.optional(decode.string),
    )
    decode.success(user_handle)
  }

  let assert Ok(user_handle) = json.parse(result, decoder)
  assert user_handle == option.None
}

pub fn decode_registration_options_roundtrip_test() {
  use inputs <- qcheck.given(qcheck.tuple4(
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    qcheck.string(),
    qcheck.string(),
  ))
  let #(challenge, user_id, rp_name, user_display_name) = inputs
  let json_string =
    build_registration_options(
      RegistrationFixture(
        ..default_registration_fixture(),
        challenge: bit_array.base64_url_encode(challenge, False),
        user_id: bit_array.base64_url_encode(user_id, False),
        rp_name:,
        user_display_name:,
      ),
    )
  let assert Ok(opt) =
    decode.run(to_dynamic(json_string), glasskey.registration_options_decoder())
  assert opt.challenge == challenge
  assert opt.user_id == user_id
  assert opt.rp_name == rp_name
  assert opt.user_display_name == user_display_name
}
