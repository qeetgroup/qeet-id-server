// Thin wrappers around the browser WebAuthn ceremony used by passkey sign-in
// and enrollment. They convert the backend's JSON options into the structured
// credential-request/creation options (preferring the native
// parse*OptionsFromJSON helpers where available) and return the assertion /
// attestation as JSON ready to POST back. Ceremony failures surface as
// WebAuthnError so callers can tell "unsupported" / "cancelled" apart from
// transport errors.

import { WebAuthnError } from "./errors.js";

type PublicKeyCredentialWithJSON = PublicKeyCredential & { toJSON?: () => unknown };

type PKCStatic = typeof PublicKeyCredential & {
  parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions;
  parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions;
};

/** True when the current browser can perform passkey ceremonies. */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    !!navigator.credentials
  );
}

function pkc(): PKCStatic {
  if (!isWebAuthnSupported()) {
    throw new WebAuthnError("unsupported", "Passkeys aren't supported in this browser.");
  }
  return window.PublicKeyCredential as PKCStatic;
}

/** Run an authentication assertion for login/MFA and return it as JSON. */
export async function getAssertion(publicKey: unknown): Promise<unknown> {
  const PK = pkc();
  const options = PK.parseRequestOptionsFromJSON
    ? PK.parseRequestOptionsFromJSON(publicKey)
    : (publicKey as PublicKeyCredentialRequestOptions);
  let assertion: PublicKeyCredentialWithJSON | null;
  try {
    assertion = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredentialWithJSON | null;
  } catch (e) {
    throw new WebAuthnError("cancelled", (e as Error).message || "Passkey request was cancelled.");
  }
  if (!assertion) throw new WebAuthnError("cancelled", "No passkey was selected.");
  return assertion.toJSON ? assertion.toJSON() : assertion;
}

/** Create a new credential (passkey enrollment) and return it as JSON. */
export async function createCredential(publicKey: unknown): Promise<unknown> {
  const PK = pkc();
  const options = PK.parseCreationOptionsFromJSON
    ? PK.parseCreationOptionsFromJSON(publicKey)
    : (publicKey as PublicKeyCredentialCreationOptions);
  let credential: PublicKeyCredentialWithJSON | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey: options,
    })) as PublicKeyCredentialWithJSON | null;
  } catch (e) {
    throw new WebAuthnError("cancelled", (e as Error).message || "Passkey creation was cancelled.");
  }
  if (!credential) throw new WebAuthnError("failed", "Passkey creation failed.");
  return credential.toJSON ? credential.toJSON() : credential;
}
