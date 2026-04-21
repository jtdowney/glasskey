import gleam/uri.{type Uri}
import lustre/attribute.{type Attribute}

pub type Route {
  Home
  Register
  Login
  Welcome
  NotFound(uri: Uri)
}

pub fn parse(uri: Uri) -> Route {
  case uri.path_segments(uri.path) {
    [] -> Home
    [""] -> Home
    ["register"] -> Register
    ["login"] -> Login
    ["welcome"] -> Welcome
    _ -> NotFound(uri:)
  }
}

pub fn to_path(route: Route) -> String {
  case route {
    Home -> "/"
    Register -> "/register"
    Login -> "/login"
    Welcome -> "/welcome"
    NotFound(uri:) -> uri.path
  }
}

pub fn href(route: Route) -> Attribute(msg) {
  attribute.href(to_path(route))
}
