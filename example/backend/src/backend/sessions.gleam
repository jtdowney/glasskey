import glasslock/authentication
import glasslock/registration
import gleam/dict.{type Dict}
import gleam/erlang/process
import gleam/otp/actor
import gleam/result
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}

const max_sessions = 1000

const session_ttl_seconds = 300.0

pub type Authentication {
  Authentication(challenge: authentication.Challenge)
}

pub type Registration {
  Registration(
    username: String,
    user_id: BitArray,
    challenge: registration.Challenge,
  )
}

pub type Store =
  process.Subject(Message)

pub opaque type Message {
  SetRegistration(session_id: String, data: Registration)
  SetAuthentication(session_id: String, data: Authentication)
  GetAndDeleteRegistration(
    session_id: String,
    reply: process.Subject(Result(Registration, Nil)),
  )
  GetAndDeleteAuthentication(
    session_id: String,
    reply: process.Subject(Result(Authentication, Nil)),
  )
}

type State {
  State(
    registrations: Dict(String, Stored(Registration)),
    authentications: Dict(String, Stored(Authentication)),
  )
}

type Stored(a) {
  Stored(data: a, created_at: Timestamp)
}

pub fn start() -> Result(Store, actor.StartError) {
  actor.new(State(registrations: dict.new(), authentications: dict.new()))
  |> actor.on_message(handle_message)
  |> actor.start
  |> result.map(fn(started) { started.data })
}

pub fn get_and_delete_authentication(
  store: Store,
  id: String,
) -> Result(Authentication, Nil) {
  actor.call(store, waiting: 1000, sending: fn(reply) {
    GetAndDeleteAuthentication(id, reply)
  })
}

pub fn set_authentication(
  store: Store,
  id: String,
  session: Authentication,
) -> Nil {
  actor.send(store, SetAuthentication(id, session))
}

pub fn get_and_delete_registration(
  store: Store,
  id: String,
) -> Result(Registration, Nil) {
  actor.call(store, waiting: 1000, sending: fn(reply) {
    GetAndDeleteRegistration(id, reply)
  })
}

pub fn set_registration(store: Store, id: String, session: Registration) -> Nil {
  actor.send(store, SetRegistration(id, session))
}

fn handle_message(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    SetRegistration(session_id, data) -> {
      let stored = Stored(data:, created_at: timestamp.system_time())
      let registrations = dict.insert(state.registrations, session_id, stored)
      actor.continue(maybe_sweep(State(..state, registrations:)))
    }
    SetAuthentication(session_id, data) -> {
      let stored = Stored(data:, created_at: timestamp.system_time())
      let authentications =
        dict.insert(state.authentications, session_id, stored)
      actor.continue(maybe_sweep(State(..state, authentications:)))
    }
    GetAndDeleteRegistration(session_id, reply) -> {
      let #(registrations, result) =
        lookup_and_delete(state.registrations, session_id)
      process.send(reply, result)
      actor.continue(State(..state, registrations:))
    }
    GetAndDeleteAuthentication(session_id, reply) -> {
      let #(authentications, result) =
        lookup_and_delete(state.authentications, session_id)
      process.send(reply, result)
      actor.continue(State(..state, authentications:))
    }
  }
}

fn lookup_and_delete(
  sessions: Dict(String, Stored(a)),
  id: String,
) -> #(Dict(String, Stored(a)), Result(a, Nil)) {
  case dict.get(sessions, id) {
    Error(_) -> #(sessions, Error(Nil))
    Ok(stored) -> {
      let age =
        timestamp.difference(stored.created_at, timestamp.system_time())
        |> duration.to_seconds
      case age >. session_ttl_seconds {
        True -> #(dict.delete(sessions, id), Error(Nil))
        False -> #(dict.delete(sessions, id), Ok(stored.data))
      }
    }
  }
}

fn maybe_sweep(state: State) -> State {
  let total = dict.size(state.registrations) + dict.size(state.authentications)
  case total > max_sessions {
    True -> {
      let now = timestamp.system_time()
      State(
        registrations: sweep_at(state.registrations, now),
        authentications: sweep_at(state.authentications, now),
      )
    }
    False -> state
  }
}

fn sweep_at(
  sessions: Dict(String, Stored(a)),
  now: Timestamp,
) -> Dict(String, Stored(a)) {
  dict.filter(sessions, fn(_key, stored) {
    let age =
      timestamp.difference(stored.created_at, now)
      |> duration.to_seconds
    age <=. session_ttl_seconds
  })
}
