import frontend/api
import frontend/router
import glasskey
import gleam/javascript/promise.{type Promise}
import gleam/json.{type Json}
import gleam/option
import gleam/uri.{type Uri}
import lustre
import lustre/attribute
import lustre/effect.{type Effect}
import lustre/element.{type Element}
import lustre/element/html
import lustre/event
import modem

pub fn main() {
  let app = lustre.application(init, update, root)
  let assert Ok(_) = lustre.start(app, "#app", Nil)
  Nil
}

pub type Model {
  Unauthenticated(page: UnauthenticatedPage)
  Registering(username: String, phase: RegisterPhase)
  Authenticated(username: String)
}

pub type UnauthenticatedPage {
  HomePage
  LoginPage(state: LoginState, username: String)
  NotFoundPage(uri: Uri)
}

pub type RegisterPhase {
  RegisterIdle(status: RegisterStatus)
  RegisterBeginning
  RegisterAwaitingAuthenticator
  RegisterVerifying
}

pub type RegisterStatus {
  RegisterStart
  RegisterSucceeded
  RegisterFailed(message: String)
}

pub type LoginState {
  LoginCheckingAutofill
  LoginSettingUpConditional
  LoginConditional
  LoginModalBeginning
  LoginModalAwaiting
  LoginVerifying
  LoginReady
  LoginFailed(message: String)
}

pub type Msg {
  RouterChangedRoute(router.Route)

  UserTypedRegisterUsername(String)
  UserClickedRegister
  BackendBeganRegistration(Result(glasskey.RegistrationOptions, String))
  AuthenticatorFinishedRegistration(Result(Json, glasskey.Error))
  BackendFinishedRegistration(Result(Nil, String))

  UserTypedLoginUsername(String)
  UserClickedLogin
  BrowserReportedAutofillSupport(Bool)
  BackendBeganLogin(Result(glasskey.AuthenticationOptions, String))
  BackendBeganModalLogin(Result(glasskey.AuthenticationOptions, String))
  BrowserStartedConditionalAuth(Result(Nil, glasskey.Error))
  AuthenticatorFinishedLogin(Result(Json, glasskey.Error))
  AuthenticatorFinishedConditionalLogin(Result(Json, glasskey.Error))
  BackendFinishedLogin(Result(String, String))
}

fn init(_flags) -> #(Model, Effect(Msg)) {
  let starting_route = case modem.initial_uri() {
    Ok(uri) -> router.parse(uri)
    Error(_) -> router.Home
  }
  let #(m, route_effect) =
    apply_route(Unauthenticated(page: HomePage), starting_route)
  #(m, effect.batch([modem.init(on_url_change), route_effect]))
}

fn on_url_change(uri: Uri) -> Msg {
  RouterChangedRoute(router.parse(uri))
}

fn update(m: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case msg {
    RouterChangedRoute(route) -> apply_route(m, route)
    _ -> dispatch_msg(m, msg)
  }
}

fn dispatch_msg(m: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case m {
    Registering(username:, phase:) -> update_register(username, phase, msg)
    Unauthenticated(page: LoginPage(state:, username:)) ->
      update_login(state, username, msg)
    _ -> #(m, effect.none())
  }
}

fn apply_route(m: Model, route: router.Route) -> #(Model, Effect(Msg)) {
  let abort_eff = abort_in_flight_conditional(m)
  let #(next, route_eff) = case route {
    router.Home -> #(Unauthenticated(page: HomePage), effect.none())
    router.Register -> #(
      Registering(
        username: previous_username(m),
        phase: RegisterIdle(status: RegisterStart),
      ),
      effect.none(),
    )
    router.Login -> #(
      Unauthenticated(page: LoginPage(
        state: LoginCheckingAutofill,
        username: "",
      )),
      check_autofill_support_effect(),
    )
    router.Welcome -> welcome_route(m)
    router.NotFound(uri:) -> #(
      Unauthenticated(page: NotFoundPage(uri:)),
      effect.none(),
    )
  }
  #(next, effect.batch([abort_eff, route_eff]))
}

fn abort_in_flight_conditional(m: Model) -> Effect(Msg) {
  case m {
    Unauthenticated(page: LoginPage(state: LoginConditional, ..)) ->
      abort_conditional_effect()
    _ -> effect.none()
  }
}

fn welcome_route(m: Model) -> #(Model, Effect(Msg)) {
  case m {
    Authenticated(..) -> #(m, effect.none())
    Unauthenticated(..) | Registering(..) -> #(
      m,
      modem.push(router.to_path(router.Home), option.None, option.None),
    )
  }
}

fn previous_username(m: Model) -> String {
  case m {
    Registering(username:, ..) -> username
    _ -> ""
  }
}

fn registering(username: String, phase: RegisterPhase) -> Model {
  Registering(username:, phase:)
}

fn login_model(state: LoginState, username: String) -> Model {
  Unauthenticated(page: LoginPage(state:, username:))
}

fn update_register(
  username: String,
  phase: RegisterPhase,
  msg: Msg,
) -> #(Model, Effect(Msg)) {
  case phase, msg {
    RegisterIdle(..), UserTypedRegisterUsername(typed) -> #(
      registering(typed, RegisterIdle(status: RegisterStart)),
      effect.none(),
    )
    RegisterIdle(..), UserClickedRegister -> #(
      registering(username, RegisterBeginning),
      api.register_begin(username, BackendBeganRegistration),
    )
    RegisterBeginning, BackendBeganRegistration(Ok(options)) -> #(
      registering(username, RegisterAwaitingAuthenticator),
      registration_effect(options),
    )
    RegisterBeginning, BackendBeganRegistration(Error(message)) -> #(
      registering(username, RegisterIdle(status: RegisterFailed(message))),
      effect.none(),
    )
    RegisterAwaitingAuthenticator,
      AuthenticatorFinishedRegistration(Ok(response))
    -> #(
      registering(username, RegisterVerifying),
      api.register_complete(response, BackendFinishedRegistration),
    )
    RegisterAwaitingAuthenticator,
      AuthenticatorFinishedRegistration(Error(error))
    -> #(
      registering(
        username,
        RegisterIdle(status: RegisterFailed(glasskey_error_to_string(error))),
      ),
      effect.none(),
    )
    RegisterVerifying, BackendFinishedRegistration(Ok(Nil)) -> #(
      registering(username, RegisterIdle(status: RegisterSucceeded)),
      effect.none(),
    )
    RegisterVerifying, BackendFinishedRegistration(Error(message)) -> #(
      registering(username, RegisterIdle(status: RegisterFailed(message))),
      effect.none(),
    )
    _, _ -> #(registering(username, phase), effect.none())
  }
}

fn update_login(
  state: LoginState,
  username: String,
  msg: Msg,
) -> #(Model, Effect(Msg)) {
  case state, msg {
    _, UserTypedLoginUsername(typed) -> #(
      login_model(state, typed),
      effect.none(),
    )
    _, UserClickedLogin -> begin_modal_login(state, username)

    LoginCheckingAutofill, BrowserReportedAutofillSupport(True) -> #(
      login_model(LoginSettingUpConditional, username),
      api.login_begin("", BackendBeganLogin),
    )
    LoginCheckingAutofill, BrowserReportedAutofillSupport(False) -> #(
      login_model(LoginReady, username),
      effect.none(),
    )

    LoginSettingUpConditional, BackendBeganLogin(Ok(options)) -> #(
      login_model(LoginSettingUpConditional, username),
      start_conditional_authentication_effect(options),
    )
    LoginSettingUpConditional, BackendBeganLogin(Error(message)) -> #(
      login_model(LoginFailed(message:), username),
      effect.none(),
    )
    LoginSettingUpConditional, BrowserStartedConditionalAuth(Ok(Nil)) -> #(
      login_model(LoginConditional, username),
      effect.none(),
    )
    LoginSettingUpConditional, BrowserStartedConditionalAuth(Error(error)) -> #(
      login_model(
        LoginFailed(message: glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    LoginModalBeginning, BackendBeganModalLogin(Ok(options)) -> #(
      login_model(LoginModalAwaiting, username),
      authentication_effect(options),
    )
    LoginModalBeginning, BackendBeganModalLogin(Error(message)) -> #(
      login_model(LoginFailed(message:), username),
      effect.none(),
    )

    LoginModalAwaiting, AuthenticatorFinishedLogin(Ok(response)) -> #(
      login_model(LoginVerifying, username),
      api.login_complete(response, BackendFinishedLogin),
    )
    LoginModalAwaiting, AuthenticatorFinishedLogin(Error(error)) -> #(
      login_model(
        LoginFailed(message: glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    LoginConditional, AuthenticatorFinishedConditionalLogin(Ok(response)) -> #(
      login_model(LoginVerifying, username),
      api.login_complete(response, BackendFinishedLogin),
    )
    LoginConditional,
      AuthenticatorFinishedConditionalLogin(Error(glasskey.Aborted))
    -> #(login_model(LoginReady, username), effect.none())
    LoginConditional, AuthenticatorFinishedConditionalLogin(Error(error)) -> #(
      login_model(
        LoginFailed(message: glasskey_error_to_string(error)),
        username,
      ),
      effect.none(),
    )

    LoginVerifying, BackendFinishedLogin(Ok(verified_username)) -> #(
      Authenticated(username: verified_username),
      modem.push(router.to_path(router.Welcome), option.None, option.None),
    )
    LoginVerifying, BackendFinishedLogin(Error(message)) -> #(
      login_model(LoginFailed(message:), username),
      effect.none(),
    )

    _, _ -> #(login_model(state, username), effect.none())
  }
}

fn begin_modal_login(
  state: LoginState,
  username: String,
) -> #(Model, Effect(Msg)) {
  let abort_eff = case state {
    LoginConditional -> abort_conditional_effect()
    _ -> effect.none()
  }
  #(
    login_model(LoginModalBeginning, username),
    effect.batch([abort_eff, api.login_begin(username, BackendBeganModalLogin)]),
  )
}

fn glasskey_error_to_string(error: glasskey.Error) -> String {
  case error {
    glasskey.NotSupported ->
      "WebAuthn is unavailable or the authenticator does not support the requested options"
    glasskey.NotAllowed -> "Operation was not allowed or was cancelled"
    glasskey.Aborted -> "Operation was aborted"
    glasskey.SecurityError -> "Security error occurred"
    glasskey.InvalidState ->
      "Authenticator state conflict (credential may already be registered)"
    glasskey.UnknownError(message) -> "Unknown error: " <> message
  }
}

@external(javascript, "./frontend_ffi.mjs", "setPendingAbort")
fn set_pending_abort(abort: fn() -> Nil) -> Nil

@external(javascript, "./frontend_ffi.mjs", "runPendingAbort")
fn run_pending_abort() -> Nil

fn dispatch_promise(promise: Promise(a), to_msg: fn(a) -> Msg) -> Effect(Msg) {
  effect.from(fn(dispatch) {
    promise.map(promise, fn(value) { dispatch(to_msg(value)) })
    Nil
  })
}

fn check_autofill_support_effect() -> Effect(Msg) {
  dispatch_promise(
    glasskey.supports_webauthn_autofill(),
    BrowserReportedAutofillSupport,
  )
}

fn start_conditional_authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(Msg) {
  effect.from(fn(dispatch) {
    case glasskey.start_conditional_authentication(options) {
      Ok(conditional) -> {
        set_pending_abort(conditional.abort)
        dispatch(BrowserStartedConditionalAuth(Ok(Nil)))
        conditional.result
        |> promise.map(fn(r) {
          dispatch(AuthenticatorFinishedConditionalLogin(r))
        })
        Nil
      }
      Error(error) -> dispatch(BrowserStartedConditionalAuth(Error(error)))
    }
  })
}

fn abort_conditional_effect() -> Effect(Msg) {
  effect.from(fn(_dispatch) { run_pending_abort() })
}

fn authentication_effect(
  options: glasskey.AuthenticationOptions,
) -> Effect(Msg) {
  dispatch_promise(
    glasskey.start_authentication(options),
    AuthenticatorFinishedLogin,
  )
}

fn registration_effect(options: glasskey.RegistrationOptions) -> Effect(Msg) {
  dispatch_promise(
    glasskey.start_registration(options),
    AuthenticatorFinishedRegistration,
  )
}

fn root(m: Model) -> Element(Msg) {
  html.main([attribute.class("app")], [
    case m {
      Unauthenticated(page: HomePage) -> home()
      Unauthenticated(page: LoginPage(state:, username:)) ->
        login(state, username)
      Unauthenticated(page: NotFoundPage(uri:)) -> not_found(uri)
      Registering(username:, phase:) -> register(username, phase)
      Authenticated(username:) -> welcome(username)
    },
  ])
}

fn back_link() -> Element(Msg) {
  html.p([], [html.a([router.href(router.Home)], [html.text("Back to home")])])
}

fn home() -> Element(Msg) {
  html.div([], [
    html.h1([], [html.text("Glasskey Demo")]),
    html.p([], [html.text("WebAuthn passkey authentication demo.")]),
    html.div([attribute.class("stack")], [
      html.a([attribute.class("button"), router.href(router.Register)], [
        html.text("Register a new passkey"),
      ]),
      html.a([attribute.class("button"), router.href(router.Login)], [
        html.text("Sign in with a passkey"),
      ]),
    ]),
  ])
}

fn login(state: LoginState, username: String) -> Element(Msg) {
  let loading = is_login_loading(state)
  html.div([], [
    html.h1([], [html.text("Sign In")]),
    html.form(
      [attribute.class("stack"), event.on_submit(fn(_) { UserClickedLogin })],
      [
        // The `webauthn` autocomplete token anchors browser passkey autofill
        // during conditional mediation. When autofill is dismissed, the typed
        // value is sent to the backend so credentials are filtered to that user.
        html.input([
          attribute.type_("text"),
          attribute.name("username"),
          attribute.placeholder("Username"),
          attribute.attribute("autocomplete", "username webauthn"),
          attribute.value(username),
          attribute.disabled(loading),
          event.on_input(UserTypedLoginUsername),
        ]),
        html.button([attribute.disabled(loading)], [
          html.text("Sign in with passkey"),
        ]),
      ],
    ),
    status(login_status(state)),
    back_link(),
  ])
}

fn is_login_loading(state: LoginState) -> Bool {
  case state {
    LoginCheckingAutofill -> False
    LoginSettingUpConditional -> False
    LoginConditional -> False
    LoginReady -> False
    LoginFailed(..) -> False
    LoginModalBeginning -> True
    LoginModalAwaiting -> True
    LoginVerifying -> True
  }
}

fn login_status(state: LoginState) -> String {
  case state {
    LoginFailed(message:) -> "Error: " <> message
    _ -> ""
  }
}

fn register(username: String, phase: RegisterPhase) -> Element(Msg) {
  let loading = is_register_loading(phase)
  html.div([], [
    html.h1([], [html.text("Register")]),
    html.div([attribute.class("stack")], [
      html.input([
        attribute.type_("text"),
        attribute.placeholder("Username"),
        attribute.value(username),
        attribute.disabled(loading),
        event.on_input(UserTypedRegisterUsername),
      ]),
      html.button(
        [
          event.on_click(UserClickedRegister),
          attribute.disabled(loading || username == ""),
        ],
        [html.text("Register")],
      ),
    ]),
    status(register_status(phase)),
    back_link(),
  ])
}

fn is_register_loading(phase: RegisterPhase) -> Bool {
  case phase {
    RegisterIdle(..) -> False
    RegisterBeginning -> True
    RegisterAwaitingAuthenticator -> True
    RegisterVerifying -> True
  }
}

fn register_status(phase: RegisterPhase) -> String {
  case phase {
    RegisterIdle(status: RegisterStart) -> ""
    RegisterIdle(status: RegisterSucceeded) -> "Registration successful!"
    RegisterIdle(status: RegisterFailed(message)) -> "Error: " <> message
    _ -> ""
  }
}

fn status(text: String) -> Element(Msg) {
  case text {
    "" -> element.none()
    message -> html.p([attribute.class("status")], [html.text(message)])
  }
}

fn welcome(username: String) -> Element(Msg) {
  html.div([], [
    html.h1([], [html.text("Welcome, " <> username <> "!")]),
    html.p([], [html.text("You have successfully authenticated.")]),
    html.a([attribute.class("button"), router.href(router.Home)], [
      html.text("Log out"),
    ]),
  ])
}

fn not_found(uri: Uri) -> Element(Msg) {
  html.div([], [
    html.h1([], [html.text("Page not found")]),
    html.p([], [
      html.text("No page matches "),
      html.code([], [html.text(uri.path)]),
      html.text("."),
    ]),
    back_link(),
  ])
}
