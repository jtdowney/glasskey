import frontend/api
import frontend/model
import frontend/router
import frontend/view
import glasskey
import gleam/javascript/promise.{type Promise}
import gleam/option
import gleam/uri.{type Uri}
import lustre
import lustre/effect.{type Effect}
import modem

pub fn main() {
  let app = lustre.application(init, update, view.root)
  let assert Ok(_) = lustre.start(app, "#app", Nil)
  Nil
}

fn init(_flags) -> #(model.Model, Effect(model.Msg)) {
  let starting_route = case modem.initial_uri() {
    Ok(uri) -> router.parse(uri)
    Error(_) -> router.Home
  }
  let #(m, route_effect) =
    apply_route(
      model.Unauthenticated(page: model.HomePage, status: ""),
      starting_route,
    )
  #(m, effect.batch([modem.init(on_url_change), route_effect]))
}

fn on_url_change(uri: Uri) -> model.Msg {
  model.UserNavigatedTo(router.parse(uri))
}

fn update(m: model.Model, msg: model.Msg) -> #(model.Model, Effect(model.Msg)) {
  case msg {
    model.UserNavigatedTo(route) -> apply_route(m, route)
    model.UserTypedUsername(username) -> update_username(m, username)
    model.UserClickedRegister -> start_registration(m)
    model.UserClickedLogin -> start_modal_login(m)
    model.BackendBeganRegistration(result) -> handle_register_begin(m, result)
    model.AuthenticatorFinishedRegistration(result) ->
      handle_registration_result(m, result)
    model.BackendFinishedRegistration(result) ->
      handle_register_complete(m, result)
    model.BackendBeganLogin(result) -> handle_login_begin(m, result)
    model.BackendBeganModalLogin(result) -> handle_modal_login_begin(m, result)
    model.AuthenticatorFinishedLogin(result) -> handle_auth_result(m, result)
    model.AuthenticatorFinishedConditionalLogin(result) ->
      handle_conditional_result(m, result)
    model.BackendFinishedLogin(result) -> handle_login_complete(m, result)
  }
}

fn apply_route(
  m: model.Model,
  route: router.Route,
) -> #(model.Model, Effect(model.Msg)) {
  let m = abort_conditional(m)
  case route {
    router.Home -> #(
      model.Unauthenticated(page: model.HomePage, status: ""),
      effect.none(),
    )
    router.Register -> #(
      model.Authenticating(
        username: form_username(m),
        stage: model.RegisterIdle,
        status: "",
      ),
      effect.none(),
    )
    router.Login -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginSettingUpConditional),
        status: "",
      ),
      api.login_begin(model.BackendBeganLogin),
    )
    router.Welcome -> welcome_route(m)
    router.NotFound(uri:) -> #(
      model.Unauthenticated(page: model.NotFoundPage(uri:), status: ""),
      effect.none(),
    )
  }
}

fn welcome_route(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Authenticated(..) -> #(m, effect.none())
    model.Unauthenticated(..) | model.Authenticating(..) -> #(
      m,
      modem.push(router.to_path(router.Home), option.None, option.None),
    )
  }
}

fn form_username(m: model.Model) -> String {
  case m {
    model.Authenticating(username:, ..) -> username
    _ -> ""
  }
}

fn abort_conditional(m: model.Model) -> model.Model {
  case m {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginConditional(abort:)),
      ..,
    ) -> {
      abort()
      m
    }
    _ -> m
  }
}

fn update_username(
  m: model.Model,
  username: String,
) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Authenticating(stage:, status:, ..) -> #(
      model.Authenticating(username:, stage:, status:),
      effect.none(),
    )
    _ -> #(m, effect.none())
  }
}

fn start_registration(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  case m {
    model.Authenticating(username:, stage: model.RegisterIdle, ..) -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterBeginning,
        status: "Starting registration...",
      ),
      api.register_begin(username, model.BackendBeganRegistration),
    )
    _ -> #(m, effect.none())
  }
}

fn handle_register_begin(
  m: model.Model,
  result: Result(glasskey.RegistrationOptions, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Authenticating(username:, stage: model.RegisterBeginning, ..),
      Ok(options)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterAwaitingAuthenticator,
        status: "Waiting for authenticator...",
      ),
      registration_effect(options),
    )
    model.Authenticating(username:, stage: model.RegisterBeginning, ..),
      Error(message)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterIdle,
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_registration_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Authenticating(
      username:,
      stage: model.RegisterAwaitingAuthenticator,
      ..,
    ),
      Ok(response)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterVerifying,
        status: "Verifying with server...",
      ),
      api.register_complete(response, model.BackendFinishedRegistration),
    )
    model.Authenticating(
      username:,
      stage: model.RegisterAwaitingAuthenticator,
      ..,
    ),
      Error(error)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterIdle,
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_register_complete(
  m: model.Model,
  result: Result(Nil, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Authenticating(username:, stage: model.RegisterVerifying, ..), Ok(Nil)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterIdle,
        status: "Registration successful!",
      ),
      effect.none(),
    )
    model.Authenticating(username:, stage: model.RegisterVerifying, ..),
      Error(message)
    -> #(
      model.Authenticating(
        username:,
        stage: model.RegisterIdle,
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn start_modal_login(m: model.Model) -> #(model.Model, Effect(model.Msg)) {
  let m = abort_conditional(m)
  case m {
    model.Unauthenticated(page: model.LoginPage(_), ..) -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginModalBeginning),
        status: "Starting authentication...",
      ),
      api.login_begin(model.BackendBeganModalLogin),
    )
    _ -> #(m, effect.none())
  }
}

fn handle_login_begin(
  m: model.Model,
  result: Result(glasskey.AuthenticationOptions, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginSettingUpConditional),
      ..,
    ),
      Ok(options)
    -> start_conditional(options)
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginSettingUpConditional),
      ..,
    ),
      Error(message)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn start_conditional(
  options: glasskey.AuthenticationOptions,
) -> #(model.Model, Effect(model.Msg)) {
  case glasskey.start_conditional_authentication(options) {
    Ok(conditional) -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginConditional(
          abort: conditional.abort,
        )),
        status: "",
      ),
      await_conditional_authentication_effect(conditional.result),
    )
    Error(_) -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "",
      ),
      effect.none(),
    )
  }
}

fn handle_modal_login_begin(
  m: model.Model,
  result: Result(glasskey.AuthenticationOptions, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginModalBeginning),
      ..,
    ),
      Ok(options)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginModalAwaiting),
        status: "Waiting for authenticator...",
      ),
      authentication_effect(options),
    )
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginModalBeginning),
      ..,
    ),
      Error(message)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_auth_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginModalAwaiting),
      ..,
    ),
      Ok(response)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginVerifying),
        status: "Verifying with server...",
      ),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginModalAwaiting),
      ..,
    ),
      Error(error)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_conditional_result(
  m: model.Model,
  result: Result(String, glasskey.Error),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginConditional(..)),
      ..,
    ),
      Ok(response)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginVerifying),
        status: "Verifying with server...",
      ),
      api.login_complete(response, model.BackendFinishedLogin),
    )
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginConditional(..)),
      status:,
    ),
      Error(glasskey.Aborted)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status:,
      ),
      effect.none(),
    )
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginConditional(..)),
      ..,
    ),
      Error(error)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> glasskey_error_to_string(error),
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn handle_login_complete(
  m: model.Model,
  result: Result(String, String),
) -> #(model.Model, Effect(model.Msg)) {
  case m, result {
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginVerifying),
      ..,
    ),
      Ok(username)
    -> #(
      model.Authenticated(username:),
      modem.push(router.to_path(router.Welcome), option.None, option.None),
    )
    model.Unauthenticated(
      page: model.LoginPage(stage: model.LoginVerifying),
      ..,
    ),
      Error(message)
    -> #(
      model.Unauthenticated(
        page: model.LoginPage(stage: model.LoginReady),
        status: "Error: " <> message,
      ),
      effect.none(),
    )
    _, _ -> #(m, effect.none())
  }
}

fn await_conditional_authentication_effect(
  result: Promise(Result(String, glasskey.Error)),
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    result
    |> promise.map(fn(r) {
      dispatch(model.AuthenticatorFinishedConditionalLogin(r))
    })
    Nil
  })
}

fn authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    glasskey.start_authentication(options)
    |> promise.map(fn(result) {
      dispatch(model.AuthenticatorFinishedLogin(result))
    })
    Nil
  })
}

fn registration_effect(
  options: glasskey.RegistrationOptions,
) -> Effect(model.Msg) {
  effect.from(fn(dispatch) {
    glasskey.start_registration(options)
    |> promise.map(fn(result) {
      dispatch(model.AuthenticatorFinishedRegistration(result))
    })
    Nil
  })
}

fn glasskey_error_to_string(error: glasskey.Error) -> String {
  case error {
    glasskey.NotSupported -> "WebAuthn is not supported in this browser"
    glasskey.NotAllowed -> "Operation was not allowed or was cancelled"
    glasskey.Aborted -> "Operation was aborted"
    glasskey.SecurityError -> "Security error occurred"
    glasskey.EncodingError(message) -> "Encoding error: " <> message
    glasskey.UnknownError(message) -> "Unknown error: " <> message
  }
}
