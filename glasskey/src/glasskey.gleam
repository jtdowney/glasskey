//// WebAuthn/FIDO2 passkey bindings for Gleam, wrapping the browser's
//// `navigator.credentials` API for registration and authentication ceremonies.
////
//// Designed for use with [glasslock](https://hexdocs.pm/glasslock) on the
//// server side, or any server that consumes JSON compatible with
//// [@simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser).

import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/javascript/array
import gleam/javascript/promise.{type Promise}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/result

/// COSE algorithm identifier for credential key pairs.
pub type Algorithm {
  /// ECDSA with P-256 and SHA-256 (COSE -7).
  Es256
  /// EdDSA with Ed25519 (COSE -8).
  Ed25519
  /// RSASSA-PKCS1-v1_5 with SHA-256 (COSE -257).
  Rs256
}

@internal
pub type AuthenticationCredential {
  AuthenticationCredential(
    id: String,
    raw_id: BitArray,
    client_data_json: BitArray,
    authenticator_data: BitArray,
    signature: BitArray,
    user_handle: Option(BitArray),
  )
}

/// Parsed authentication ceremony options from the server.
///
/// Construct with [`authentication_options_decoder`](#authentication_options_decoder).
pub opaque type AuthenticationOptions {
  AuthenticationOptions(
    /// Raw challenge bytes.
    challenge: BitArray,
    /// Relying party identifier (effective domain). `None` lets the browser
    /// fall back to the calling document's origin.
    rp_id: Option(String),
    /// Ceremony timeout in milliseconds. `None` lets the browser apply its
    /// default.
    timeout: Option(Int),
    /// User verification requirement. `None` lets the browser apply the spec
    /// default of `preferred`.
    user_verification: Option(Requirement),
    /// Credentials the user may authenticate with. An empty list selects
    /// the discoverable (passkey) flow.
    allow_credentials: List(CredentialDescriptor),
  )
}

@internal
pub fn authentication_options(
  challenge challenge: BitArray,
  rp_id rp_id: Option(String),
  timeout timeout: Option(Int),
  user_verification user_verification: Option(Requirement),
  allow_credentials allow_credentials: List(CredentialDescriptor),
) -> AuthenticationOptions {
  AuthenticationOptions(
    challenge:,
    rp_id:,
    timeout:,
    user_verification:,
    allow_credentials:,
  )
}

@internal
pub type AuthenticationOptionsFields {
  AuthenticationOptionsFields(
    challenge: BitArray,
    rp_id: Option(String),
    timeout: Option(Int),
    user_verification: Option(Requirement),
    allow_credentials: List(CredentialDescriptor),
  )
}

@internal
pub fn authentication_options_fields(
  options: AuthenticationOptions,
) -> AuthenticationOptionsFields {
  let AuthenticationOptions(
    challenge:,
    rp_id:,
    timeout:,
    user_verification:,
    allow_credentials:,
  ) = options
  AuthenticationOptionsFields(
    challenge:,
    rp_id:,
    timeout:,
    user_verification:,
    allow_credentials:,
  )
}

/// A reference to a previously registered credential, with optional
/// transport hints to help the browser route the ceremony to the right
/// authenticator.
pub type CredentialDescriptor {
  CredentialDescriptor(id: BitArray, transports: List(Transport))
}

/// Transport hints reported by the authenticator.
pub type Transport {
  /// Removable USB authenticator.
  TransportUsb
  /// Near-field communication authenticator.
  TransportNfc
  /// Bluetooth Low Energy authenticator.
  TransportBle
  /// ISO/IEC 7816 smart card.
  TransportSmartCard
  /// Cross-device authenticator (e.g. phone acting as a roaming key).
  TransportHybrid
  /// Built-in platform authenticator (Touch ID, Windows Hello, etc.).
  TransportInternal
}

@internal
pub fn transport_to_string(transport: Transport) -> String {
  case transport {
    TransportUsb -> "usb"
    TransportNfc -> "nfc"
    TransportBle -> "ble"
    TransportSmartCard -> "smart-card"
    TransportHybrid -> "hybrid"
    TransportInternal -> "internal"
  }
}

@internal
pub fn translate_dom_exception(name: String, message: String) -> Error {
  case name {
    "NotSupportedError" -> NotSupported
    "ConstraintError" -> NotSupported
    "NotAllowedError" -> NotAllowed
    "AbortError" -> Aborted
    "SecurityError" -> SecurityError
    "InvalidStateError" -> InvalidState
    _ -> UnknownError(name <> ": " <> message)
  }
}

/// Authenticator attachment modality.
pub type AuthenticatorAttachment {
  /// Built-in authenticator (Touch ID, Windows Hello, etc.).
  Platform
  /// Removable authenticator (USB security key, Bluetooth, etc.).
  CrossPlatform
}

/// Result of starting a conditional authentication ceremony.
///
/// Contains the promise that resolves when the user selects a passkey
/// from the browser's autofill UI, and an abort function to cancel
/// the pending ceremony. After calling `abort()`, `result` resolves to
/// `Error(Aborted)`.
pub type ConditionalAuthentication {
  ConditionalAuthentication(
    result: Promise(Result(Json, Error)),
    abort: fn() -> Nil,
  )
}

/// Errors returned by glasskey operations.
pub type Error {
  /// The browser or authenticator does not support what was requested.
  NotSupported
  /// The user cancelled the request or the operation timed out.
  NotAllowed
  /// The operation was aborted.
  Aborted
  /// Security policy violation (e.g., non-HTTPS origin or invalid
  /// relying party ID for this origin).
  SecurityError
  /// The operation conflicted with the authenticator's state. During
  /// registration this typically means a credential matched by
  /// `excludeCredentials` is already present; during authentication it
  /// can mean the credential has been invalidated on the authenticator.
  InvalidState
  /// An unexpected error from the browser API.
  UnknownError(String)
}

@internal
pub type RegistrationCredential {
  RegistrationCredential(
    id: String,
    raw_id: BitArray,
    client_data_json: BitArray,
    attestation_object: BitArray,
    transports: List(String),
  )
}

/// Parsed registration ceremony options from the server.
///
/// Construct with [`registration_options_decoder`](#registration_options_decoder).
pub opaque type RegistrationOptions {
  RegistrationOptions(
    /// Raw challenge bytes.
    challenge: BitArray,
    /// Relying party identifier (effective domain).
    rp_id: String,
    /// Human-readable relying party name shown to the user.
    rp_name: String,
    /// Opaque user handle as raw bytes.
    user_id: BitArray,
    /// Username shown in the browser's account chooser.
    user_name: String,
    /// Human-readable display name shown to the user.
    user_display_name: String,
    /// Accepted signing algorithms in preference order. The authenticator
    /// picks the first it supports. Always non-empty.
    algorithms: List(Algorithm),
    /// Ceremony timeout in milliseconds. `None` lets the browser apply its
    /// default.
    timeout: Option(Int),
    /// Discoverable credential requirement. `None` lets the browser apply
    /// the spec default of `discouraged`.
    resident_key: Option(Requirement),
    /// User verification requirement. `None` lets the browser apply the spec
    /// default of `preferred`.
    user_verification: Option(Requirement),
    /// Restrict the authenticator class. `None` allows any.
    authenticator_attachment: Option(AuthenticatorAttachment),
    /// Credentials to exclude (prevent re-registration of an existing
    /// authenticator).
    exclude_credentials: List(CredentialDescriptor),
  )
}

@internal
pub fn registration_options(
  challenge challenge: BitArray,
  rp_id rp_id: String,
  rp_name rp_name: String,
  user_id user_id: BitArray,
  user_name user_name: String,
  user_display_name user_display_name: String,
  algorithms algorithms: List(Algorithm),
  timeout timeout: Option(Int),
  resident_key resident_key: Option(Requirement),
  user_verification user_verification: Option(Requirement),
  authenticator_attachment authenticator_attachment: Option(
    AuthenticatorAttachment,
  ),
  exclude_credentials exclude_credentials: List(CredentialDescriptor),
) -> RegistrationOptions {
  RegistrationOptions(
    challenge:,
    rp_id:,
    rp_name:,
    user_id:,
    user_name:,
    user_display_name:,
    algorithms:,
    timeout:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  )
}

@internal
pub type RegistrationOptionsFields {
  RegistrationOptionsFields(
    challenge: BitArray,
    rp_id: String,
    rp_name: String,
    user_id: BitArray,
    user_name: String,
    user_display_name: String,
    algorithms: List(Algorithm),
    timeout: Option(Int),
    resident_key: Option(Requirement),
    user_verification: Option(Requirement),
    authenticator_attachment: Option(AuthenticatorAttachment),
    exclude_credentials: List(CredentialDescriptor),
  )
}

@internal
pub fn registration_options_fields(
  options: RegistrationOptions,
) -> RegistrationOptionsFields {
  let RegistrationOptions(
    challenge:,
    rp_id:,
    rp_name:,
    user_id:,
    user_name:,
    user_display_name:,
    algorithms:,
    timeout:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  ) = options
  RegistrationOptionsFields(
    challenge:,
    rp_id:,
    rp_name:,
    user_id:,
    user_name:,
    user_display_name:,
    algorithms:,
    timeout:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  )
}

/// WebAuthn requirement level for resident keys or user verification.
pub type Requirement {
  /// Require the authenticator to satisfy the request.
  Required
  /// Request the capability, but accept a response without it.
  Preferred
  /// Ask the authenticator to omit the capability when possible. Common for
  /// `resident_key`; unusual for `user_verification`, where it permits
  /// presence-only authentication.
  Discouraged
}

type AuthenticatorSelection {
  AuthenticatorSelection(
    resident_key: Option(Requirement),
    user_verification: Option(Requirement),
    authenticator_attachment: Option(AuthenticatorAttachment),
  )
}

type CreateOptions {
  CreateOptions(
    challenge: BitArray,
    rp: Rp,
    user: User,
    pub_key_cred_params: array.Array(Int),
    timeout: Option(Int),
    authenticator_selection: Option(AuthenticatorSelection),
    exclude_credentials: array.Array(CredentialDescriptor),
  )
}

type GetOptions {
  GetOptions(
    challenge: BitArray,
    rp_id: Option(String),
    timeout: Option(Int),
    user_verification: Option(Requirement),
    allow_credentials: array.Array(CredentialDescriptor),
  )
}

type Rp {
  Rp(id: String, name: String)
}

type User {
  User(id: BitArray, name: String, display_name: String)
}

/// Start the WebAuthn authentication ceremony.
///
/// Takes options parsed with [`authentication_options_decoder`](#authentication_options_decoder),
/// then calls `navigator.credentials.get`. Returns a promise resolving to
/// the assertion response as a `Json` value. Serialize and send to your
/// server (e.g. as the body to `glasslock/authentication.verify_json`),
/// or embed it in a larger envelope and decode it server-side with
/// `glasslock/authentication.response_decoder()` before calling
/// `glasslock/authentication.verify`.
pub fn start_authentication(
  options: AuthenticationOptions,
) -> Promise(Result(Json, Error)) {
  use <- bool.guard(
    when: !supports_webauthn(),
    return: promise.resolve(Error(NotSupported)),
  )

  get_credential(to_get_options(options))
  |> promise.map(result.map(_, encode_authentication_response))
}

/// Start a conditional WebAuthn authentication ceremony (autofill UI).
///
/// Unlike [`start_authentication`](#start_authentication) which shows a modal browser prompt,
/// this surfaces passkey suggestions in the browser's autofill dropdown.
/// Requires an `<input autocomplete="username webauthn">` element on the page.
///
/// Takes options parsed with [`authentication_options_decoder`](#authentication_options_decoder).
/// Returns synchronously with the ceremony handle or an error. Call `abort`
/// before starting a modal ceremony or when navigating away.
pub fn start_conditional_authentication(
  options: AuthenticationOptions,
) -> Result(ConditionalAuthentication, Error) {
  use <- bool.guard(when: !supports_webauthn(), return: Error(NotSupported))

  let #(raw_promise, abort) =
    get_conditional_credential(to_get_options(options))
  let result =
    raw_promise
    |> promise.map(result.map(_, encode_authentication_response))

  Ok(ConditionalAuthentication(result:, abort:))
}

@external(javascript, "./glasskey_ffi.mjs", "getConditionalCredential")
fn get_conditional_credential(
  options: GetOptions,
) -> #(Promise(Result(AuthenticationCredential, Error)), fn() -> Nil)

@external(javascript, "./glasskey_ffi.mjs", "getCredential")
fn get_credential(
  options: GetOptions,
) -> Promise(Result(AuthenticationCredential, Error))

fn to_get_options(options: AuthenticationOptions) -> GetOptions {
  GetOptions(
    challenge: options.challenge,
    rp_id: options.rp_id,
    timeout: options.timeout,
    user_verification: options.user_verification,
    allow_credentials: array.from_list(options.allow_credentials),
  )
}

/// Check whether the browser supports a user-verifying platform authenticator (Touch ID, Windows Hello, etc.).
@external(javascript, "./glasskey_ffi.mjs", "platformAuthenticatorIsAvailable")
pub fn supports_platform_authenticator() -> Promise(Bool)

/// Check whether the browser supports WebAuthn.
///
/// Returns `True` if both `window.PublicKeyCredential` and
/// `navigator.credentials` are available.
@external(javascript, "./glasskey_ffi.mjs", "browserSupportsWebauthn")
pub fn supports_webauthn() -> Bool

/// Check whether the browser supports WebAuthn autofill (conditional mediation).
@external(javascript, "./glasskey_ffi.mjs", "isConditionalMediationAvailable")
pub fn supports_webauthn_autofill() -> Promise(Bool)

fn encode_authentication_response(
  credential: AuthenticationCredential,
) -> Json {
  let base_fields = [
    #("clientDataJSON", base64url_json(credential.client_data_json)),
    #("authenticatorData", base64url_json(credential.authenticator_data)),
    #("signature", base64url_json(credential.signature)),
  ]
  let response_fields = case credential.user_handle {
    option.Some(handle) -> [
      #("userHandle", base64url_json(handle)),
      ..base_fields
    ]
    option.None -> base_fields
  }

  json.object([
    #("id", json.string(credential.id)),
    #("rawId", base64url_json(credential.raw_id)),
    #("type", json.string("public-key")),
    #("response", json.object(response_fields)),
  ])
}

fn encode_registration_response(credential: RegistrationCredential) -> Json {
  let response_fields = [
    #("clientDataJSON", base64url_json(credential.client_data_json)),
    #("attestationObject", base64url_json(credential.attestation_object)),
  ]
  let response_fields = case credential.transports {
    [] -> response_fields
    _ -> [
      #("transports", json.array(credential.transports, json.string)),
      ..response_fields
    ]
  }

  json.object([
    #("id", json.string(credential.id)),
    #("rawId", base64url_json(credential.raw_id)),
    #("type", json.string("public-key")),
    #("response", json.object(response_fields)),
  ])
}

fn base64url_json(bytes: BitArray) -> Json {
  json.string(bit_array.base64_url_encode(bytes, False))
}

/// Decoder for the `PublicKeyCredentialRequestOptionsJSON` shape produced by
/// `glasslock/authentication.build`.
///
/// Use this when decoding the server's envelope response so the `options`
/// subtree comes out as a typed `AuthenticationOptions` ready to pass to
/// [`start_authentication`](#start_authentication) or
/// [`start_conditional_authentication`](#start_conditional_authentication).
pub fn authentication_options_decoder() -> decode.Decoder(AuthenticationOptions) {
  use challenge <- decode.field("challenge", base64url_decoder())
  use rp_id <- decode.optional_field(
    "rpId",
    option.None,
    decode.optional(decode.string),
  )
  use timeout <- decode.optional_field(
    "timeout",
    option.None,
    decode.optional(decode.int),
  )
  use user_verification <- decode.optional_field(
    "userVerification",
    option.None,
    decode.optional(requirement_decoder()),
  )
  use allow_credentials <- decode.optional_field(
    "allowCredentials",
    [],
    credential_descriptor_list_decoder(),
  )
  decode.success(AuthenticationOptions(
    challenge:,
    rp_id:,
    timeout:,
    user_verification:,
    allow_credentials:,
  ))
}

/// Decoder for the `PublicKeyCredentialCreationOptionsJSON` shape produced by
/// `glasslock/registration.build`.
///
/// Use this when decoding the server's envelope response so the `options`
/// subtree comes out as a typed `RegistrationOptions` ready to pass to
/// [`start_registration`](#start_registration).
pub fn registration_options_decoder() -> decode.Decoder(RegistrationOptions) {
  use challenge <- decode.field("challenge", base64url_decoder())
  use rp_id <- decode.subfield(["rp", "id"], decode.string)
  use rp_name <- decode.subfield(["rp", "name"], decode.string)
  use user_id <- decode.subfield(["user", "id"], base64url_decoder())
  use user_name <- decode.subfield(["user", "name"], decode.string)
  use user_display_name <- decode.subfield(
    ["user", "displayName"],
    decode.string,
  )
  use algorithms <- decode.field(
    "pubKeyCredParams",
    pub_key_cred_params_decoder(),
  )
  use timeout <- decode.optional_field(
    "timeout",
    option.None,
    decode.optional(decode.int),
  )
  use #(resident_key, user_verification, authenticator_attachment) <- decode.optional_field(
    "authenticatorSelection",
    #(option.None, option.None, option.None),
    authenticator_selection_decoder(),
  )
  use exclude_credentials <- decode.optional_field(
    "excludeCredentials",
    [],
    credential_descriptor_list_decoder(),
  )
  decode.success(RegistrationOptions(
    challenge:,
    rp_id:,
    rp_name:,
    user_id:,
    user_name:,
    user_display_name:,
    algorithms:,
    timeout:,
    resident_key:,
    user_verification:,
    authenticator_attachment:,
    exclude_credentials:,
  ))
}

fn algorithm_from_cose(alg: Int) -> Result(Algorithm, Nil) {
  case alg {
    -7 -> Ok(Es256)
    -8 -> Ok(Ed25519)
    -257 -> Ok(Rs256)
    _ -> Error(Nil)
  }
}

fn pub_key_cred_params_decoder() -> decode.Decoder(List(Algorithm)) {
  let entry = {
    use _ <- decode.field("type", public_key_credential_type_decoder())
    use alg <- decode.field("alg", decode.int)
    decode.success(alg)
  }
  decode.list(entry)
  |> decode.map(list.filter_map(_, algorithm_from_cose))
  |> decode.then(require_non_empty_algorithms)
}

fn require_non_empty_algorithms(
  algs: List(Algorithm),
) -> decode.Decoder(List(Algorithm)) {
  case algs {
    [] -> decode.failure([], "non-empty pubKeyCredParams")
    _ -> decode.success(algs)
  }
}

fn authenticator_selection_decoder() -> decode.Decoder(
  #(Option(Requirement), Option(Requirement), Option(AuthenticatorAttachment)),
) {
  use resident_key <- decode.optional_field(
    "residentKey",
    option.None,
    decode.optional(requirement_decoder()),
  )
  use user_verification <- decode.optional_field(
    "userVerification",
    option.None,
    decode.optional(requirement_decoder()),
  )
  use authenticator_attachment <- decode.optional_field(
    "authenticatorAttachment",
    option.None,
    decode.optional(authenticator_attachment_decoder()),
  )
  decode.success(#(resident_key, user_verification, authenticator_attachment))
}

fn authenticator_attachment_decoder() -> decode.Decoder(AuthenticatorAttachment) {
  decode.string
  |> decode.then(fn(s) {
    case s {
      "platform" -> decode.success(Platform)
      "cross-platform" -> decode.success(CrossPlatform)
      _ -> decode.failure(CrossPlatform, "authenticatorAttachment")
    }
  })
}

fn base64url_decoder() -> decode.Decoder(BitArray) {
  decode.string
  |> decode.then(fn(s) {
    case bit_array.base64_url_decode(s) {
      Ok(bytes) -> decode.success(bytes)
      Error(_) -> decode.failure(<<>>, "base64url")
    }
  })
}

fn credential_descriptor_list_decoder() -> decode.Decoder(
  List(CredentialDescriptor),
) {
  decode.list({
    use _ <- decode.field("type", public_key_credential_type_decoder())
    use id <- decode.field("id", base64url_decoder())
    use transport_strings <- decode.optional_field(
      "transports",
      [],
      decode.list(decode.string),
    )
    decode.success(CredentialDescriptor(
      id:,
      transports: list.filter_map(transport_strings, transport_from_string),
    ))
  })
}

fn transport_from_string(value: String) -> Result(Transport, Nil) {
  case value {
    "usb" -> Ok(TransportUsb)
    "nfc" -> Ok(TransportNfc)
    "ble" -> Ok(TransportBle)
    "smart-card" -> Ok(TransportSmartCard)
    "hybrid" -> Ok(TransportHybrid)
    "internal" -> Ok(TransportInternal)
    _ -> Error(Nil)
  }
}

fn public_key_credential_type_decoder() -> decode.Decoder(Nil) {
  decode.string
  |> decode.then(fn(type_) {
    case type_ {
      "public-key" -> decode.success(Nil)
      _ -> decode.failure(Nil, "public-key credential type")
    }
  })
}

fn requirement_decoder() -> decode.Decoder(Requirement) {
  decode.string
  |> decode.then(fn(s) {
    case s {
      "required" -> decode.success(Required)
      "preferred" -> decode.success(Preferred)
      "discouraged" -> decode.success(Discouraged)
      _ -> decode.failure(Preferred, "requirement")
    }
  })
}

/// Start the WebAuthn registration ceremony.
///
/// Takes options parsed with [`registration_options_decoder`](#registration_options_decoder),
/// then calls `navigator.credentials.create`. Returns a promise resolving
/// to the credential response as a `Json` value. Serialize and send to
/// your server (e.g. as the body to
/// `glasslock/registration.verify_json`), or embed it in a larger
/// envelope and decode it server-side with
/// `glasslock/registration.response_decoder()` before calling
/// `glasslock/registration.verify`.
pub fn start_registration(
  options: RegistrationOptions,
) -> Promise(Result(Json, Error)) {
  use <- bool.guard(
    when: !supports_webauthn(),
    return: promise.resolve(Error(NotSupported)),
  )

  create_credential(to_create_options(options))
  |> promise.map(result.map(_, encode_registration_response))
}

fn to_create_options(options: RegistrationOptions) -> CreateOptions {
  let authenticator_selection = case
    options.resident_key,
    options.user_verification,
    options.authenticator_attachment
  {
    option.None, option.None, option.None -> option.None
    resident_key, user_verification, authenticator_attachment ->
      option.Some(AuthenticatorSelection(
        resident_key:,
        user_verification:,
        authenticator_attachment:,
      ))
  }

  CreateOptions(
    challenge: options.challenge,
    rp: Rp(id: options.rp_id, name: options.rp_name),
    user: User(
      id: options.user_id,
      name: options.user_name,
      display_name: options.user_display_name,
    ),
    pub_key_cred_params: array.from_list(list.map(
      options.algorithms,
      algorithm_to_cose,
    )),
    timeout: options.timeout,
    authenticator_selection:,
    exclude_credentials: array.from_list(options.exclude_credentials),
  )
}

@external(javascript, "./glasskey_ffi.mjs", "createCredential")
fn create_credential(
  options: CreateOptions,
) -> Promise(Result(RegistrationCredential, Error))

fn algorithm_to_cose(algorithm: Algorithm) -> Int {
  case algorithm {
    Es256 -> -7
    Ed25519 -> -8
    Rs256 -> -257
  }
}

@internal
pub fn authenticator_attachment_to_string(
  attachment: AuthenticatorAttachment,
) -> String {
  case attachment {
    Platform -> "platform"
    CrossPlatform -> "cross-platform"
  }
}

@internal
pub fn requirement_to_string(requirement: Requirement) -> String {
  case requirement {
    Required -> "required"
    Preferred -> "preferred"
    Discouraged -> "discouraged"
  }
}
