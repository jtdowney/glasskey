import glasslock
import glasslock/internal/cbor
import glasslock/testing
import gleam/bit_array
import gleam/list
import gose
import gose/cose
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh
import unitest

pub fn main() -> Nil {
  unitest.main()
}

pub fn parse_public_key_round_trip_preserves_algorithm_test() {
  let cases = [
    #(testing.generate_es256_keypair, gose.Ecdsa(gose.EcdsaP256)),
    #(testing.generate_ed25519_keypair, gose.Eddsa),
    #(testing.generate_rs256_keypair, gose.RsaPkcs1(gose.RsaPkcs1Sha256)),
  ]

  list.each(cases, fn(test_case) {
    let #(generate, expected_algorithm) = test_case
    let keypair = generate()
    let cose_bytes = testing.cose_key(keypair)
    let assert Ok(public_key) = glasslock.parse_public_key(cose_bytes)
    assert glasslock.public_key_alg(public_key) == expected_algorithm
    assert glasslock.encode_public_key(public_key) == cose_bytes
  })
}

pub fn parse_public_key_rejects_invalid_cbor_test() {
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(<<0xFF, 0xFF, 0xFF>>)
}

pub fn parse_public_key_rejects_non_map_cbor_test() {
  let cbor_bytes = cbor.encode(cbor.String("not a map"))
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_unsupported_key_type_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(99)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  assert glasslock.parse_public_key(cbor_bytes)
    == Error(glasslock.InvalidPublicKey("unsupported COSE key type: 99"))
}

pub fn parse_public_key_rejects_unsupported_curve_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(99)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_invalid_coordinates_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:128>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_alg_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(4)),
      #(cbor.Int(-1), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  assert glasslock.parse_public_key(cbor_bytes)
    == Error(glasslock.UnsupportedPublicKey(
      "COSE key missing algorithm (label 3)",
    ))
}

pub fn parse_public_key_rejects_non_signature_algorithm_test() {
  let key =
    gose.generate_ec(ec.P256)
    |> gose.with_alg(gose.KeyEncryptionAlg(gose.EcdhEs(gose.EcdhEsDirect)))
  let assert Ok(public) = gose.public_key(key)
  let assert Ok(cose_bytes) = cose.key_to_cbor(public)
  assert glasslock.parse_public_key(cose_bytes)
    == Error(glasslock.UnsupportedPublicKey(
      "key algorithm is not a signature algorithm",
    ))
}

pub fn parse_public_key_rejects_missing_kty_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_x_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_missing_y_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_non_integer_kty_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.String("EC")),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_non_bytes_x_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(2)),
      #(cbor.Int(3), cbor.Int(-7)),
      #(cbor.Int(-1), cbor.Int(1)),
      #(cbor.Int(-2), cbor.Int(42)),
      #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_okp_missing_curve_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(1)),
      #(cbor.Int(3), cbor.Int(-8)),
      #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_rsa_missing_n_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(3)),
      #(cbor.Int(3), cbor.Int(-257)),
      #(cbor.Int(-2), cbor.Bytes(<<1, 0, 1>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

pub fn parse_public_key_rejects_rsa_missing_e_test() {
  let cose_map =
    cbor.Map([
      #(cbor.Int(1), cbor.Int(3)),
      #(cbor.Int(3), cbor.Int(-257)),
      #(cbor.Int(-1), cbor.Bytes(<<0:2048>>)),
    ])
  let cbor_bytes = cbor.encode(cose_map)
  let assert Error(glasslock.InvalidPublicKey(_)) =
    glasslock.parse_public_key(cbor_bytes)
}

fn encode_key_with_alg(
  key: cose.Key,
  alg alg: gose.DigitalSignatureAlg,
) -> BitArray {
  let assert Ok(bytes) =
    key
    |> gose.with_alg(gose.SigningAlg(gose.DigitalSignature(alg)))
    |> cose.key_to_cbor
  bytes
}

fn encode_map_in_order(entries: List(#(cbor.Cbor, cbor.Cbor))) -> BitArray {
  let count = list.length(entries)
  let payload =
    list.map(entries, fn(entry) {
      bit_array.concat([cbor.encode(entry.0), cbor.encode(entry.1)])
    })
    |> bit_array.concat
  bit_array.concat([<<5:3, count:5>>, payload])
}

pub fn parse_public_key_canonicalizes_encoding_test() {
  let canonical = testing.generate_es256_keypair() |> testing.cose_key
  let assert Ok(cbor.Map(entries)) = cbor.decode_all(canonical)
  let noncanonical = entries |> list.reverse |> encode_map_in_order
  assert noncanonical != canonical

  let assert Ok(public_key) = glasslock.parse_public_key(noncanonical)
  assert glasslock.encode_public_key(public_key) == canonical
}

pub fn parse_public_key_rejects_symmetric_and_xdh_keys_test() {
  let assert Ok(symmetric) = gose.from_octet_bits(<<0:256>>)
  let assert Ok(xdh_public) =
    gose.generate_xdh(xdh.X25519)
    |> gose.public_key

  let keys = [
    #(symmetric, gose.Ecdsa(gose.EcdsaP256)),
    #(xdh_public, gose.Eddsa),
  ]
  list.each(keys, fn(entry) {
    let assert Error(_) =
      encode_key_with_alg(entry.0, alg: entry.1)
      |> glasslock.parse_public_key
  })
}

pub fn parse_public_key_rejects_private_parameters_test() {
  let assert Ok(rsa) = gose.generate_rsa(2048)
  let keys = [
    #(gose.generate_ec(ec.P256), gose.Ecdsa(gose.EcdsaP256)),
    #(gose.generate_eddsa(eddsa.Ed25519), gose.Eddsa),
    #(rsa, gose.RsaPkcs1(gose.RsaPkcs1Sha256)),
  ]
  list.each(keys, fn(entry) {
    let assert Error(_) =
      encode_key_with_alg(entry.0, alg: entry.1)
      |> glasslock.parse_public_key
  })
}

pub fn parse_public_key_rejects_optional_parameters_test() {
  let assert Ok(public) =
    gose.generate_ec(ec.P256)
    |> gose.public_key
  let bytes =
    public
    |> gose.with_kid_bits(<<1, 2, 3, 4>>)
    |> encode_key_with_alg(alg: gose.Ecdsa(gose.EcdsaP256))

  let assert Error(_) = glasslock.parse_public_key(bytes)
}

pub fn parse_public_key_rejects_algorithm_and_curve_mismatches_test() {
  let assert Ok(ec_public) =
    gose.generate_ec(ec.P256)
    |> gose.public_key
  let assert Ok(p384_public) =
    gose.generate_ec(ec.P384)
    |> gose.public_key
  let assert Ok(ed25519_public) =
    gose.generate_eddsa(eddsa.Ed25519)
    |> gose.public_key
  let assert Ok(rsa) = gose.generate_rsa(2048)
  let assert Ok(rsa_public) = gose.public_key(rsa)

  let keys = [
    #(ec_public, gose.Eddsa),
    #(p384_public, gose.Ecdsa(gose.EcdsaP256)),
    #(ed25519_public, gose.Ecdsa(gose.EcdsaP256)),
    #(rsa_public, gose.Ecdsa(gose.EcdsaP256)),
  ]
  list.each(keys, fn(entry) {
    let assert Error(_) =
      encode_key_with_alg(entry.0, alg: entry.1)
      |> glasslock.parse_public_key
  })
}
