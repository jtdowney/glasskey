import backend/credentials
import backend/sessions
import wisp

pub type Context {
  Context(
    sessions: sessions.Store,
    credentials: credentials.Store,
    rp_id: String,
    rp_name: String,
    origin: String,
  )
}

pub fn middleware(
  req: wisp.Request,
  ctx: Context,
  handler: fn(wisp.Request) -> wisp.Response,
) -> wisp.Response {
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes

  handler(req)
  |> add_cors_headers(ctx)
}

fn add_cors_headers(response: wisp.Response, ctx: Context) -> wisp.Response {
  response
  |> wisp.set_header("access-control-allow-origin", ctx.origin)
  |> wisp.set_header("access-control-allow-methods", "POST, OPTIONS")
  |> wisp.set_header("access-control-allow-headers", "content-type")
  |> wisp.set_header("vary", "origin")
}
