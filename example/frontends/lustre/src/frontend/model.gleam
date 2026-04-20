import glasskey

pub type Model {
  Model(page: Page, username: String, status: String)
}

pub type Page {
  HomePage
  RegisterPage(stage: RegisterStage)
  LoginPage(stage: LoginStage)
  WelcomePage(username: String)
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

pub type Destination {
  DestHome
  DestRegister
  DestLogin
}

pub type Msg {
  NavigateTo(Destination)
  UsernameChanged(String)
  RegisterClicked
  GotRegisterBeginResponse(Result(glasskey.RegistrationOptions, String))
  GotWebAuthnRegistrationResult(Result(String, glasskey.Error))
  GotRegisterCompleteResponse(Result(Nil, String))
  LoginClicked
  GotLoginBeginResponse(Result(glasskey.AuthenticationOptions, String))
  GotModalLoginBeginResponse(Result(glasskey.AuthenticationOptions, String))
  GotWebAuthnAuthenticationResult(Result(String, glasskey.Error))
  GotConditionalAuthenticationResult(Result(String, glasskey.Error))
  GotLoginCompleteResponse(Result(String, String))
}
