//// Server-side WebAuthn/FIDO2 credential verification for Gleam.

import glasslock/internal/cbor
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gose
import gose/cose

/// User-verification policy for a ceremony.
pub type Verification {
  /// Reject unless the authenticator verifies the user with a biometric or PIN.
  VerificationRequired
  /// Request verification, but accept a response without it.
  VerificationPreferred
  /// Ask the authenticator to skip verification when possible.
  VerificationDiscouraged
}

/// A COSE-encoded public key.
///
/// Round-trip through storage with [`parse_public_key`](#parse_public_key)
/// and [`encode_public_key`](#encode_public_key).
pub opaque type PublicKey {
  PublicKey(bytes: BitArray, key: cose.Key, alg: gose.DigitalSignatureAlg)
}

/// Errors returned by [`parse_public_key`](#parse_public_key) when stored
/// bytes cannot be interpreted as a supported COSE public key.
pub type PublicKeyError {
  /// The bytes are not a valid COSE-encoded public key.
  InvalidPublicKey(reason: String)
  /// The key uses an algorithm or curve glasslock does not support.
  UnsupportedPublicKey(reason: String)
}

/// Parse stored COSE bytes into a `PublicKey`.
///
/// Validates the encoding, key type, curve, and signature algorithm. Use
/// when loading a credential from storage before passing to
/// `authentication.verify`.
pub fn parse_public_key(bytes: BitArray) -> Result(PublicKey, PublicKeyError) {
  use key_cbor <- result.try(
    cbor.decode_all(bytes)
    |> result.map_error(InvalidPublicKey),
  )
  let canonical_bytes = cbor.encode(key_cbor)
  use parsed_key <- result.try(
    cose.key_from_cbor(canonical_bytes)
    |> result.map_error(map_gose_error_to_public_key_error),
  )
  use sig_alg <- result.try(extract_signature_alg(parsed_key))
  use _ <- result.try(validate_public_key_cbor(key_cbor))
  Ok(PublicKey(bytes: canonical_bytes, key: parsed_key, alg: sig_alg))
}

/// Serialize a `PublicKey` to canonical public-only COSE bytes.
///
/// The returned bytes round-trip through [`parse_public_key`](#parse_public_key). Use when
/// persisting a credential to storage.
pub fn encode_public_key(public_key: PublicKey) -> BitArray {
  public_key.bytes
}

@internal
pub fn public_key_cose(public_key: PublicKey) -> cose.Key {
  public_key.key
}

@internal
pub fn public_key_alg(public_key: PublicKey) -> gose.DigitalSignatureAlg {
  public_key.alg
}

fn extract_signature_alg(
  key: cose.Key,
) -> Result(gose.DigitalSignatureAlg, PublicKeyError) {
  case gose.alg(key) {
    Ok(gose.SigningAlg(gose.DigitalSignature(sig_alg))) -> Ok(sig_alg)
    Ok(_) ->
      Error(UnsupportedPublicKey("key algorithm is not a signature algorithm"))
    Error(_) ->
      Error(UnsupportedPublicKey("COSE key missing algorithm (label 3)"))
  }
}

fn validate_public_key_cbor(key: cbor.Cbor) -> Result(Nil, PublicKeyError) {
  case key {
    cbor.Map(entries) -> {
      use key_type <- result.try(public_key_int(entries, label: 1, name: "kty"))
      use algorithm <- result.try(public_key_int(entries, label: 3, name: "alg"))
      case key_type, algorithm {
        2, -7 ->
          validate_curve_and_labels(
            entries,
            labels: [1, 3, -1, -2, -3],
            expected_curve: 1,
          )
        1, -8 ->
          validate_curve_and_labels(
            entries,
            labels: [1, 3, -1, -2],
            expected_curve: 6,
          )
        3, -257 -> validate_labels(entries, expected: [1, 3, -1, -2])
        _, _ ->
          Error(UnsupportedPublicKey(
            "unsupported WebAuthn key type or algorithm",
          ))
      }
    }
    cbor.Int(_) | cbor.Bytes(_) | cbor.String(_) ->
      Error(InvalidPublicKey("COSE_Key must be a CBOR map"))
  }
}

fn validate_curve_and_labels(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  labels labels: List(Int),
  expected_curve expected_curve: Int,
) -> Result(Nil, PublicKeyError) {
  use _ <- result.try(validate_labels(entries, expected: labels))
  use curve <- result.try(public_key_int(entries, label: -1, name: "curve"))
  use <- bool.guard(
    when: curve != expected_curve,
    return: Error(UnsupportedPublicKey("unsupported WebAuthn key curve")),
  )
  Ok(Nil)
}

fn validate_labels(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  expected expected: List(Int),
) -> Result(Nil, PublicKeyError) {
  use labels <- result.try(
    list.try_map(entries, fn(entry) {
      case entry.0 {
        cbor.Int(label) -> Ok(label)
        cbor.Bytes(_) | cbor.String(_) | cbor.Map(_) ->
          Error(InvalidPublicKey("COSE_Key labels must be integers"))
      }
    }),
  )
  use <- bool.guard(
    when: list.sort(labels, int.compare) != list.sort(expected, int.compare),
    return: Error(InvalidPublicKey(
      "credential public key contains missing, duplicate, or forbidden parameters",
    )),
  )
  Ok(Nil)
}

fn public_key_int(
  entries: List(#(cbor.Cbor, cbor.Cbor)),
  label label: Int,
  name name: String,
) -> Result(Int, PublicKeyError) {
  case list.key_find(entries, cbor.Int(label)) {
    Ok(cbor.Int(value)) -> Ok(value)
    Ok(cbor.Bytes(_)) | Ok(cbor.String(_)) | Ok(cbor.Map(_)) ->
      Error(InvalidPublicKey(name <> " must be an integer"))
    Error(_) -> Error(InvalidPublicKey("missing " <> name))
  }
}

fn map_gose_error_to_public_key_error(err: gose.GoseError) -> PublicKeyError {
  case err {
    gose.ParseError(msg) -> InvalidPublicKey(msg)
    gose.CryptoError(msg) -> UnsupportedPublicKey(msg)
    gose.VerificationFailed -> InvalidPublicKey("verification failed")
    gose.InvalidState(msg) -> UnsupportedPublicKey(msg)
  }
}

/// Transport hints reported by an authenticator during registration.
///
/// Echoed back to the browser in `allow_credentials`/`exclude_credentials` so
/// it can route the request to the right authenticator. Optional for
/// correctness; helpful for UX, especially with hybrid (cross-device)
/// transports.
pub type Transport {
  /// Removable USB authenticator.
  TransportUsb
  /// Near-field communication authenticator.
  TransportNfc
  /// Bluetooth Low Energy authenticator.
  TransportBle
  /// ISO/IEC 7816 smart card with contacts.
  TransportSmartCard
  /// Cross-device authenticator (e.g. phone acting as a roaming key).
  TransportHybrid
  /// Built-in platform authenticator (Touch ID, Windows Hello, etc.).
  TransportInternal
}

/// A reference to a stored credential, used in `allow_credentials` and
/// `exclude_credentials` lists. Carrying transports is optional but lets the
/// browser route the ceremony to the right authenticator faster.
pub type CredentialDescriptor {
  CredentialDescriptor(id: BitArray, transports: List(Transport))
}

/// A verified WebAuthn credential returned after successful registration or authentication.
///
/// Persist every field after registration. After authentication, replace the
/// stored `sign_count` with the value returned by `authentication.verify`.
/// Pass `id` and `transports` to `registration.exclude_credential` or
/// `authentication.allow_credential` when starting another ceremony.
pub type Credential {
  Credential(
    /// Authenticator-generated identifier.
    id: BitArray,
    /// COSE public key used to verify assertions.
    public_key: PublicKey,
    /// Latest authenticator signature counter.
    sign_count: Int,
    /// Browser transport hints reported at registration.
    transports: List(Transport),
  )
}

/// Identifies which field failed verification in a `VerificationMismatch` error.
pub type VerificationField {
  /// The `type` field in clientDataJSON (expected `"webauthn.create"` or `"webauthn.get"`).
  TypeField
  /// The `challenge` field in clientDataJSON did not match the expected challenge bytes.
  ChallengeField
  /// The `origin` field in clientDataJSON did not match the expected origin.
  OriginField
  /// The SHA-256 hash of the Relying Party ID did not match authenticator data.
  RelyingPartyIdField
  /// The `crossOrigin` field was `true` but cross-origin requests are not allowed.
  CrossOriginField
  /// The `topOrigin` field was either set without `crossOrigin: true`, or did
  /// not match any allowed top-level origin.
  TopOriginField
  /// The `rawId` in the response did not match the credential ID in authenticator data.
  CredentialIdField
  /// The top-level credential `type` field was not `"public-key"`.
  CredentialTypeField
  /// The assertion `userHandle` was missing or did not match the account.
  UserHandleField
}
