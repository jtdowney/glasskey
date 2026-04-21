import { BitArray$BitArray, Result$Ok, Result$Error } from "./gleam.mjs";
import {
  Option$Some,
  Option$None,
  Option$isSome,
  Option$Some$0,
} from "../gleam_stdlib/gleam/option.mjs";
import {
  Error$NotSupported,
  Error$NotAllowed,
  Error$Aborted,
  Error$SecurityError,
  Error$UnknownError,
} from "./glasskey.mjs";

export function browserSupportsWebauthn() {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined"
  );
}

function toPublicKeyCredParams(params) {
  return params.map((p) => ({ type: p.type_, alg: p.alg }));
}

function toCredentialDescriptors(descriptors) {
  return descriptors.map((d) => ({ type: d.type_, id: d.id.rawBuffer }));
}

export async function createCredential(opts) {
  const publicKey = {
    challenge: opts.challenge.rawBuffer,
    rp: opts.rp,
    user: {
      id: opts.user.id.rawBuffer,
      name: opts.user.name,
      displayName: opts.user.display_name,
    },
    pubKeyCredParams: toPublicKeyCredParams(opts.pub_key_cred_params),
    attestation: opts.attestation,
    authenticatorSelection: {
      residentKey: opts.authenticator_selection.resident_key,
      userVerification: opts.authenticator_selection.user_verification,
    },
  };

  if (opts.timeout > 0) {
    publicKey.timeout = opts.timeout;
  }

  if (Option$isSome(opts.authenticator_selection.authenticator_attachment)) {
    publicKey.authenticatorSelection.authenticatorAttachment = Option$Some$0(
      opts.authenticator_selection.authenticator_attachment,
    );
  }

  if (opts.exclude_credentials.length > 0) {
    publicKey.excludeCredentials = toCredentialDescriptors(
      opts.exclude_credentials,
    );
  }

  try {
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      return Result$Error(Error$NotAllowed());
    }
    return Result$Ok(extractRegistrationFields(credential));
  } catch (error) {
    return Result$Error(classifyJsError(error));
  }
}

export async function getCredential(opts) {
  const publicKey = {
    challenge: opts.challenge.rawBuffer,
    userVerification: opts.user_verification,
  };

  if (opts.rp_id) {
    publicKey.rpId = opts.rp_id;
  }

  if (opts.timeout > 0) {
    publicKey.timeout = opts.timeout;
  }

  if (opts.allow_credentials.length > 0) {
    publicKey.allowCredentials = toCredentialDescriptors(
      opts.allow_credentials,
    );
  }

  try {
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) {
      return Result$Error(Error$NotAllowed());
    }

    return Result$Ok(extractAuthenticationFields(credential));
  } catch (error) {
    return Result$Error(classifyJsError(error));
  }
}

export function getConditionalCredential(opts) {
  const controller = new AbortController();
  const publicKey = {
    challenge: opts.challenge.rawBuffer,
    userVerification: opts.user_verification,
  };

  if (opts.rp_id) {
    publicKey.rpId = opts.rp_id;
  }

  if (opts.timeout > 0) {
    publicKey.timeout = opts.timeout;
  }

  if (opts.allow_credentials.length > 0) {
    publicKey.allowCredentials = toCredentialDescriptors(
      opts.allow_credentials,
    );
  }

  const promise = navigator.credentials
    .get({
      publicKey,
      mediation: "conditional",
      signal: controller.signal,
    })
    .then((credential) => {
      if (!credential) {
        return Result$Error(Error$NotAllowed());
      }
      return Result$Ok(extractAuthenticationFields(credential));
    })
    .catch((error) => Result$Error(classifyJsError(error)));

  return [promise, () => controller.abort()];
}

function extractRegistrationFields(credential) {
  return {
    id: credential.id,
    raw_id: BitArray$BitArray(new Uint8Array(credential.rawId)),
    client_data_json: BitArray$BitArray(
      new Uint8Array(credential.response.clientDataJSON),
    ),
    attestation_object: BitArray$BitArray(
      new Uint8Array(credential.response.attestationObject),
    ),
  };
}

function extractAuthenticationFields(credential) {
  const user_handle = credential.response.userHandle
    ? Option$Some(
        BitArray$BitArray(new Uint8Array(credential.response.userHandle)),
      )
    : Option$None();

  return {
    id: credential.id,
    raw_id: BitArray$BitArray(new Uint8Array(credential.rawId)),
    client_data_json: BitArray$BitArray(
      new Uint8Array(credential.response.clientDataJSON),
    ),
    authenticator_data: BitArray$BitArray(
      new Uint8Array(credential.response.authenticatorData),
    ),
    signature: BitArray$BitArray(new Uint8Array(credential.response.signature)),
    user_handle,
  };
}

function classifyJsError(error) {
  if (error instanceof DOMException) {
    switch (error.name) {
      case "NotSupportedError":
        return Error$NotSupported();
      case "NotAllowedError":
        return Error$NotAllowed();
      case "AbortError":
        return Error$Aborted();
      case "SecurityError":
        return Error$SecurityError();
      default:
        return Error$UnknownError(error.name + ": " + error.message);
    }
  }
  if (error instanceof Error) {
    return Error$UnknownError(error.message);
  }
  return Error$UnknownError(String(error));
}

export async function platformAuthenticatorIsAvailable() {
  if (
    !browserSupportsWebauthn() ||
    typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !==
      "function"
  ) {
    return false;
  }
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

export async function isConditionalMediationAvailable() {
  if (
    !browserSupportsWebauthn() ||
    typeof PublicKeyCredential.isConditionalMediationAvailable !== "function"
  ) {
    return false;
  }
  return PublicKeyCredential.isConditionalMediationAvailable();
}
