//// Credential store backed by storail

import glasslock
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import storail

fn user_to_json(user: User) -> json.Json {
  json.object([
    #("username", json.string(user.username)),
    #("user_id", json.string(bit_array.base64_encode(user.user_id, True))),
    #("credentials", json.array(user.credentials, credential_to_json)),
  ])
}

fn credential_to_json(credential: glasslock.Credential) -> json.Json {
  json.object([
    #("id", json.string(bit_array.base64_encode(credential.id, True))),
    #(
      "public_key_bytes",
      json.string(bit_array.base64_encode(
        glasslock.encode_public_key(credential.public_key),
        True,
      )),
    ),
    #("sign_count", json.int(credential.sign_count)),
    #(
      "transports",
      json.array(credential.transports, fn(t) {
        json.string(transport_to_string(t))
      }),
    ),
  ])
}

fn user_decoder() -> decode.Decoder(User) {
  use username <- decode.field("username", decode.string)
  use user_id <- decode.field("user_id", base64_decoder())
  use credentials <- decode.field(
    "credentials",
    decode.list(credential_decoder()),
  )
  case result.all(credentials) {
    Ok(credentials) -> decode.success(User(username:, user_id:, credentials:))
    Error(Nil) ->
      decode.failure(User(username: "", user_id: <<>>, credentials: []), "User")
  }
}

fn credential_decoder() -> decode.Decoder(Result(glasslock.Credential, Nil)) {
  use id <- decode.field("id", base64_decoder())
  use public_key_bytes <- decode.field("public_key_bytes", base64_decoder())
  use sign_count <- decode.field("sign_count", decode.int)
  use transports <- decode.field("transports", decode.list(transport_decoder()))
  decode.success(
    glasslock.parse_public_key(public_key_bytes)
    |> result.replace_error(Nil)
    |> result.map(fn(public_key) {
      glasslock.Credential(id:, public_key:, sign_count:, transports:)
    }),
  )
}

fn base64_decoder() -> decode.Decoder(BitArray) {
  use text <- decode.then(decode.string)
  case bit_array.base64_decode(text) {
    Ok(bytes) -> decode.success(bytes)
    Error(Nil) -> decode.failure(<<>>, "Base64")
  }
}

fn transport_decoder() -> decode.Decoder(glasslock.Transport) {
  use text <- decode.then(decode.string)
  case transport_from_string(text) {
    Ok(transport) -> decode.success(transport)
    Error(Nil) -> decode.failure(glasslock.TransportInternal, "Transport")
  }
}

fn transport_to_string(transport: glasslock.Transport) -> String {
  case transport {
    glasslock.TransportUsb -> "usb"
    glasslock.TransportNfc -> "nfc"
    glasslock.TransportBle -> "ble"
    glasslock.TransportSmartCard -> "smart-card"
    glasslock.TransportHybrid -> "hybrid"
    glasslock.TransportInternal -> "internal"
  }
}

fn transport_from_string(value: String) -> Result(glasslock.Transport, Nil) {
  case value {
    "usb" -> Ok(glasslock.TransportUsb)
    "nfc" -> Ok(glasslock.TransportNfc)
    "ble" -> Ok(glasslock.TransportBle)
    "smart-card" -> Ok(glasslock.TransportSmartCard)
    "hybrid" -> Ok(glasslock.TransportHybrid)
    "internal" -> Ok(glasslock.TransportInternal)
    _ -> Error(Nil)
  }
}

pub opaque type Store {
  Store(
    users: storail.Collection(User),
    credential_index: storail.Collection(String),
    user_id_index: storail.Collection(String),
  )
}

pub type User {
  User(
    username: String,
    user_id: BitArray,
    credentials: List(glasslock.Credential),
  )
}

pub fn open(storage_path: String) -> Store {
  let config = storail.Config(storage_path:)
  let users =
    storail.Collection(
      name: "users",
      to_json: user_to_json,
      decoder: user_decoder(),
      config:,
    )
  let credential_index =
    storail.Collection(
      name: "credential_index",
      to_json: json.string,
      decoder: decode.string,
      config:,
    )
  let user_id_index =
    storail.Collection(
      name: "user_id_index",
      to_json: json.string,
      decoder: decode.string,
      config:,
    )
  Store(users:, credential_index:, user_id_index:)
}

fn user_key(username: String) -> String {
  username
  |> bit_array.from_string
  |> bit_array.base64_url_encode(False)
}

pub fn get_user(store: Store, username: String) -> Result(User, Nil) {
  storail.read(storail.key(store.users, user_key(username)))
  |> result.replace_error(Nil)
}

pub fn get_user_by_credential_id(
  store: Store,
  credential_id: BitArray,
) -> Result(User, Nil) {
  storail.read(storail.key(
    store.credential_index,
    bit_array.base64_url_encode(credential_id, False),
  ))
  |> result.replace_error(Nil)
  |> result.try(get_user(store, _))
}

pub fn get_user_by_user_id(
  store: Store,
  user_id: BitArray,
) -> Result(User, Nil) {
  storail.read(storail.key(
    store.user_id_index,
    bit_array.base64_url_encode(user_id, False),
  ))
  |> result.replace_error(Nil)
  |> result.try(get_user(store, _))
}

pub type SaveError {
  UsernameTaken
  CredentialIdTaken
  UserIdTaken
}

pub fn save(
  store: Store,
  username: String,
  user_id: BitArray,
  credential: glasslock.Credential,
) -> Result(Nil, SaveError) {
  let cred_key = bit_array.base64_url_encode(credential.id, False)
  let uid_key = bit_array.base64_url_encode(user_id, False)

  use <- bool.guard(
    exists(storail.key(store.users, user_key(username))),
    Error(UsernameTaken),
  )
  use <- bool.guard(
    exists(storail.key(store.credential_index, cred_key)),
    Error(CredentialIdTaken),
  )
  use <- bool.guard(
    exists(storail.key(store.user_id_index, uid_key)),
    Error(UserIdTaken),
  )

  let user = User(username:, user_id:, credentials: [credential])
  // this is a demo, don't ignore write errors for real use
  let _ = storail.write(storail.key(store.users, user_key(username)), user)
  let _ = storail.write(storail.key(store.credential_index, cred_key), username)
  let _ = storail.write(storail.key(store.user_id_index, uid_key), username)
  Ok(Nil)
}

pub fn update(
  store: Store,
  user: User,
  credential: glasslock.Credential,
) -> Nil {
  let updated_user =
    User(..user, credentials: replace_credential(user.credentials, credential))
  let _ =
    storail.write(
      storail.key(store.users, user_key(user.username)),
      updated_user,
    )
  Nil
}

fn exists(key: storail.Key(t)) -> Bool {
  case storail.optional_read(key) {
    Ok(option.Some(_)) -> True
    _ -> False
  }
}

fn replace_credential(
  credentials: List(glasslock.Credential),
  updated: glasslock.Credential,
) -> List(glasslock.Credential) {
  list.map(credentials, fn(cred) {
    case cred.id == updated.id {
      True -> updated
      False -> cred
    }
  })
}
