import backend/credentials
import backend/web
import glasslock
import glasslock/registration
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import non_empty_list
import snag.{type Result}
import wisp

const session_cookie = "registration"

// Five-minute lifetime for the pending-ceremony cookie. Bounds how long a
// half-completed registration can sit before the user must restart.
const session_max_age = 300

type PendingRegistration {
  PendingRegistration(
    username: String,
    user_id: BitArray,
    challenge: registration.Challenge,
  )
}

pub fn begin(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use username <- decode.field("username", decode.string)
    decode.success(username)
  }

  case json.parse(body, decoder) |> result.map(string.trim) {
    Ok("") -> web.error_response("username required", 400)
    Ok(trimmed) -> begin_registration(req, trimmed, ctx)
    Error(_) -> web.error_response("invalid json", 400)
  }
}

pub fn complete(req: wisp.Request, ctx: web.Context) -> wisp.Response {
  use body <- wisp.require_string_body(req)

  let decoder = {
    use response <- decode.field("response", registration.response_decoder())
    decode.success(response)
  }

  case json.parse(body, decoder) {
    Error(_) -> web.error_response("invalid json", 400)
    Ok(response) -> complete_registration(req, response, ctx)
  }
}

fn begin_registration(
  req: wisp.Request,
  username: String,
  ctx: web.Context,
) -> wisp.Response {
  case credentials.get_user(ctx.credentials, username) {
    Ok(_) -> web.error_response("username already registered", 409)
    Error(_) -> {
      // Random opaque user handle. WebAuthn requires user.id to contain
      // no PII so credentials can't be used to correlate accounts across
      // relying parties.
      let user_id = registration.random_user_id()

      // Resident key is required so the credential lives on the authenticator
      // and the demo can exercise the discoverable (passkey) sign-in flow.
      let builder =
        registration.new(
          relying_party: registration.RelyingParty(
            id: ctx.rp_id,
            name: ctx.rp_name,
          ),
          user: registration.User(
            id: user_id,
            name: username,
            display_name: username,
          ),
          origin: non_empty_list.first(ctx.origins),
        )
        |> registration.resident_key(registration.ResidentKeyRequired)
        |> registration.user_verification(glasslock.VerificationPreferred)
      let #(options_json, challenge) =
        list.fold(
          non_empty_list.rest(ctx.origins),
          builder,
          registration.origin,
        )
        |> registration.build()

      let pending =
        encode_pending(PendingRegistration(username:, user_id:, challenge:))

      json.object([#("options", options_json)])
      |> json.to_string
      |> wisp.json_response(200)
      |> wisp.set_cookie(
        req,
        session_cookie,
        pending,
        wisp.Signed,
        session_max_age,
      )
    }
  }
}

fn complete_registration(
  req: wisp.Request,
  response: registration.Response,
  ctx: web.Context,
) -> wisp.Response {
  let result = {
    use raw <- result.try(
      wisp.get_cookie(req, session_cookie, wisp.Signed)
      |> snag.replace_error("session not found"),
    )
    use session <- result.try(decode_pending(raw))
    use credential <- result.try(
      registration.verify(response:, challenge: session.challenge)
      |> snag.replace_error("verification failed"),
    )
    Ok(#(session, credential))
  }

  case result {
    Error(error) ->
      web.error_response(snag.line_print(error), 400)
      |> web.clear_session(req, session_cookie)
    Ok(#(session, credential)) ->
      case
        credentials.save(
          ctx.credentials,
          session.username,
          session.user_id,
          credential,
        )
      {
        Ok(_) ->
          json.object([#("verified", json.bool(True))])
          |> json.to_string
          |> wisp.json_response(200)
          |> web.clear_session(req, session_cookie)
        Error(error) ->
          web.error_response(snag.line_print(error), 409)
          |> web.clear_session(req, session_cookie)
      }
  }
}

fn encode_pending(pending: PendingRegistration) -> String {
  json.object([
    #("username", json.string(pending.username)),
    #(
      "user_id",
      json.string(bit_array.base64_url_encode(pending.user_id, False)),
    ),
    #(
      "challenge",
      json.string(registration.encode_challenge(pending.challenge)),
    ),
  ])
  |> json.to_string
}

fn decode_pending(raw: String) -> Result(PendingRegistration) {
  let decoder = {
    use username <- decode.field("username", decode.string)
    use user_id_b64 <- decode.field("user_id", decode.string)
    use challenge_encoded <- decode.field("challenge", decode.string)
    decode.success(#(username, user_id_b64, challenge_encoded))
  }

  use #(username, user_id_b64, challenge_encoded) <- result.try(
    json.parse(raw, decoder)
    |> snag.replace_error("invalid session"),
  )
  use user_id <- result.try(
    bit_array.base64_url_decode(user_id_b64)
    |> snag.replace_error("invalid session"),
  )
  use challenge <- result.try(
    registration.parse_challenge(challenge_encoded)
    |> snag.replace_error("invalid session"),
  )
  Ok(PendingRegistration(username:, user_id:, challenge:))
}
