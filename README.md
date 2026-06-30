# glasskey

WebAuthn/FIDO2 passkey authentication for Gleam.

Two independent libraries, linked by shared JSON convention:

| Package                 | Target             | Description                       |
| ----------------------- | ------------------ | --------------------------------- |
| [glasslock](glasslock/) | Erlang / NodeJS    | Server-side WebAuthn verification |
| [glasskey](glasskey/)   | Browser JavaScript | Browser WebAuthn bindings         |

The libraries are independent at compile time, glasskey produces JSON that glasslock consumes by convention.

## Installation

```sh
# Server (Erlang target)
gleam add glasslock

# Browser (JavaScript target)
gleam add glasskey
```

## Example Apps

The `example/` directory contains a shared Wisp/Mist backend (using glasslock) and two interchangeable frontends that talk to it:

- `example/backend/` - Wisp/Mist server (port 3000) that accepts requests from either frontend.
- `example/frontends/lustre/` - Lustre using glasskey.
- `example/frontends/svelte/` - SvelteKit using `@simplewebauthn/browser`.

```sh
just example-lustre  # Run the Lustre-based demo
just example-svelte  # Run the Svelte/SimpleWebAuthn demo
```

## Resources

- [passkeys.dev](https://passkeys.dev) - developer-focused passkey documentation
- [WebAuthn Guide](https://webauthn.guide) - interactive WebAuthn explainer
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) - full specification
