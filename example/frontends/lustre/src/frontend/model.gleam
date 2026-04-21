import frontend/router
import glasskey
import gleam/uri.{type Uri}

pub type Model {
  Unauthenticated(page: UnauthenticatedPage, status: String)
  Authenticating(username: String, stage: RegisterStage, status: String)
  Authenticated(username: String, status: String)
}

pub type UnauthenticatedPage {
  HomePage
  LoginPage(stage: LoginStage)
  NotFoundPage(uri: Uri)
}

pub type RegisterStage {
  RegisterIdle
  RegisterBeginning
  RegisterAwaitingAuthenticator
  RegisterVerifying
}

pub type LoginStage {
  LoginSettingUpConditional
  LoginConditional(abort: fn() -> Nil)
  LoginModalBeginning
  LoginModalAwaiting
  LoginVerifying
  LoginReady
}

pub type Msg {
  UserNavigatedTo(router.Route)
  UserTypedUsername(String)
  UserClickedRegister
  UserClickedLogin
  BackendBeganRegistration(Result(glasskey.RegistrationOptions, String))
  AuthenticatorFinishedRegistration(Result(String, glasskey.Error))
  BackendFinishedRegistration(Result(Nil, String))
  BackendBeganLogin(Result(glasskey.AuthenticationOptions, String))
  BackendBeganModalLogin(Result(glasskey.AuthenticationOptions, String))
  AuthenticatorFinishedLogin(Result(String, glasskey.Error))
  AuthenticatorFinishedConditionalLogin(Result(String, glasskey.Error))
  BackendFinishedLogin(Result(String, String))
}
