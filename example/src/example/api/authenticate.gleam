import example/api/helpers
import example/store/credentials
import example/store/sessions.{AuthenticationSession}
import example/web.{type Context}
import glasskeys/authentication
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import wisp.{type Request, type Response}

pub fn begin(_req: Request, ctx: Context) -> Response {
  let defaults = authentication.default_options()
  let options =
    authentication.Options(
      ..defaults,
      rp_id: ctx.rp_id,
      origin: ctx.origin,
      allow_credentials: [],
    )

  let #(options_json, challenge) = authentication.generate_options(options)

  let session_id = helpers.generate_session_id()
  sessions.set(ctx.session_store, session_id, AuthenticationSession(challenge))

  // Wrap the options JSON with session_id for the frontend
  let response_json =
    json.object([
      #("session_id", json.string(session_id)),
      #("options", json.string(options_json)),
    ])

  wisp.json_response(json.to_string(response_json), 200)
}

pub fn complete(req: Request, ctx: Context) -> Response {
  use json_body <- wisp.require_json(req)

  let decoder = {
    use session_id <- decode.field("session_id", decode.string)
    use response <- decode.field("response", decode.string)
    decode.success(#(session_id, response))
  }

  let decode_result = decode.run(json_body, decoder)
  use <- bool.guard(
    when: result.is_error(decode_result),
    return: helpers.json_error("Invalid request", 400),
  )
  let assert Ok(#(session_id, response_json)) = decode_result

  let session_result = sessions.get(ctx.session_store, session_id)
  use <- bool.guard(
    when: result.is_error(session_result),
    return: helpers.json_error("Session not found", 400),
  )
  let assert Ok(session) = session_result
  sessions.delete(ctx.session_store, session_id)

  let challenge_result = require_auth_session(session)
  use <- bool.guard(
    when: result.is_error(challenge_result),
    return: helpers.json_error("Invalid session type", 400),
  )
  let assert Ok(challenge) = challenge_result

  // Parse response to get credential_id and user_handle for lookup
  let info_result = authentication.parse_response(response_json)
  use <- bool.lazy_guard(when: result.is_error(info_result), return: fn() {
    let assert Error(e) = info_result
    helpers.json_error(helpers.error_to_string(e), 400)
  })
  let assert Ok(info) = info_result

  let user_result = find_user(ctx, info.credential_id, info.user_handle)
  use <- bool.guard(
    when: result.is_error(user_result),
    return: helpers.json_error("User not found", 400),
  )
  let assert Ok(user) = user_result

  let stored_cred_result =
    list.find(user.credentials, fn(c) { c.id == info.credential_id })
  use <- bool.guard(
    when: result.is_error(stored_cred_result),
    return: helpers.json_error("Credential not found", 400),
  )
  let assert Ok(stored_cred) = stored_cred_result

  let verify_result =
    authentication.verify(
      response_json: response_json,
      challenge: challenge,
      stored: stored_cred,
    )
  use <- bool.lazy_guard(when: result.is_error(verify_result), return: fn() {
    let assert Error(e) = verify_result
    helpers.json_error(helpers.error_to_string(e), 400)
  })
  let assert Ok(updated_credential) = verify_result

  let update_result =
    credentials.update(ctx.credential_store, user.username, updated_credential)
  use <- bool.guard(
    when: result.is_error(update_result),
    return: helpers.json_error("Failed to update credential", 500),
  )

  wisp.redirect("/welcome")
  |> web.set_session_cookie(req, user.username)
}

fn find_user(
  ctx: Context,
  credential_id: BitArray,
  user_handle: option.Option(BitArray),
) -> Result(credentials.User, Nil) {
  case user_handle {
    Some(user_id) -> {
      use user <- result.try(credentials.get_user_by_user_id(
        ctx.credential_store,
        user_id,
      ))
      case list.find(user.credentials, fn(c) { c.id == credential_id }) {
        Ok(_) -> Ok(user)
        Error(_) -> Error(Nil)
      }
    }
    None ->
      credentials.get_user_by_credential_id(ctx.credential_store, credential_id)
  }
}

fn require_auth_session(
  session: sessions.SessionData,
) -> Result(authentication.Challenge, Nil) {
  case session {
    sessions.AuthenticationSession(challenge) -> Ok(challenge)
    _ -> Error(Nil)
  }
}
