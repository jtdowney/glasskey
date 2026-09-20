import glasskey
import gleam/dynamic/decode
import gleam/http/response.{type Response}
import gleam/json.{type Json}
import gleam/result
import lustre/effect.{type Effect}
import rsvp
import snag.{type Result}

pub fn login_begin(
  username: String,
  handler: fn(Result(glasskey.AuthenticationOptions)) -> msg,
) -> Effect(msg) {
  let body = json.object([#("username", json.string(username))])

  let expect =
    rsvp.expect_ok_response(fn(result) {
      handler(decode_options(
        snag.map_error(result, rsvp_error_message),
        glasskey.authentication_options_decoder(),
      ))
    })

  rsvp.post("/api/login/begin", body, expect)
}

pub fn login_complete(
  response: Json,
  handler: fn(Result(String)) -> msg,
) -> Effect(msg) {
  let body = json.object([#("response", response)])

  let expect =
    rsvp.expect_ok_response(fn(result) {
      handler(decode_login_result(snag.map_error(result, rsvp_error_message)))
    })

  rsvp.post("/api/login/complete", body, expect)
}

pub fn register_begin(
  username: String,
  handler: fn(Result(glasskey.RegistrationOptions)) -> msg,
) -> Effect(msg) {
  let body = json.object([#("username", json.string(username))])

  let expect =
    rsvp.expect_ok_response(fn(result) {
      handler(decode_options(
        snag.map_error(result, rsvp_error_message),
        glasskey.registration_options_decoder(),
      ))
    })

  rsvp.post("/api/register/begin", body, expect)
}

pub fn register_complete(
  response: Json,
  handler: fn(Result(Nil)) -> msg,
) -> Effect(msg) {
  let body = json.object([#("response", response)])

  let expect =
    rsvp.expect_ok_response(fn(result) {
      handler(decode_verified(snag.map_error(result, rsvp_error_message)))
    })

  rsvp.post("/api/register/complete", body, expect)
}

fn decode_login_result(result: Result(Response(String))) -> Result(String) {
  let decoder = {
    use verified <- decode.field("verified", decode.bool)
    use username <- decode.field("username", decode.string)
    decode.success(#(verified, username))
  }
  case decode_response(result, decoder) {
    Ok(#(True, username)) -> Ok(username)
    Ok(#(False, _)) -> snag.error("Verification failed")
    Error(error) -> Error(error)
  }
}

fn decode_response(
  result: Result(Response(String)),
  decoder: decode.Decoder(a),
) -> Result(a) {
  case result {
    Error(error) -> Error(error)
    Ok(resp) ->
      json.parse(resp.body, decoder)
      |> snag.replace_error("Invalid response from server")
  }
}

fn decode_options(
  result: Result(Response(String)),
  options_decoder: decode.Decoder(a),
) -> Result(a) {
  let decoder = {
    use options <- decode.field("options", options_decoder)
    decode.success(options)
  }
  decode_response(result, decoder)
}

fn decode_verified(result: Result(Response(String))) -> Result(Nil) {
  let decoder = {
    use verified <- decode.field("verified", decode.bool)
    decode.success(verified)
  }

  use verified <- result.try(decode_response(result, decoder))
  case verified {
    True -> Ok(Nil)
    False -> snag.error("Verification failed")
  }
}

fn rsvp_error_message(error: rsvp.Error(String)) -> String {
  case error {
    rsvp.HttpError(resp) -> {
      let error_decoder = {
        use msg <- decode.field("error", decode.string)
        decode.success(msg)
      }
      case json.parse(resp.body, error_decoder) {
        Ok(msg) -> msg
        Error(_) -> "Server error"
      }
    }
    rsvp.NetworkError -> "Network error"
    rsvp.BadBody | rsvp.JsonError(_) -> "Invalid response from server"
    rsvp.BadUrl(_) | rsvp.UnhandledResponse(_) -> "Unexpected response"
  }
}
