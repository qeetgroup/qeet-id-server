# ADR-0010: Passkeys (WebAuthn/FIDO2) as Primary Authentication

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Password-based authentication is phishable, reusable across sites, and the root cause of a large fraction of account compromises. The FIDO Alliance's WebAuthn/FIDO2 standard (passkeys) provides hardware-bound, phish-resistant authentication that is now supported across all major browsers, OS platforms, and mobile devices.

Qeet ID's positioning as an "Auth0/Okta alternative" requires it to lead on modern authentication, not catch up to it. The question was whether passkeys should be:

1. **An add-on** — passwords first, passkeys optionally bolted on later
2. **Primary, with password fallback** — passkeys built in from day one as an equal or preferred option

## Decision

**Passkeys are a first-class authentication method** built in from the beginning:

- WebAuthn implementation: `go-webauthn` library (`domains/access/passkeys`)
- Registration: `POST /v1/passkeys/register/begin` + `/complete`
- Authentication: `POST /v1/passkeys/login/begin` + `/complete`
- Challenge sessions stored in `auth.webauthn_sessions` with **5-minute TTL** (freshness guarantee, replay defense)
- Passkeys and passwords are both fully supported; neither requires the other

The hosted login app (`apps/login`) presents passkeys as the primary option with password as an alternative.

## Consequences

**Positive:**
- Phish-resistant by design: the authenticator (device/OS) verifies the origin before signing the assertion — a phishing site cannot capture and replay a passkey assertion
- Hardware-bound credentials cannot be exfiltrated (private key never leaves the device's secure enclave)
- No shared secret: no password hash to steal from the database
- Meets modern enterprise security requirements (many enterprise security policies now require phish-resistant MFA)

**Negative / watch-outs:**
- Requires modern browser/OS support (all major platforms as of 2024, but some enterprise environments lag behind with update policies)
- Account recovery requires a non-passkey path (magic-link/OTP to registered email) when a device is lost
- The 5-minute WebAuthn session TTL means the registration/authentication ceremony must complete within 5 minutes of challenge issuance — timeouts require restarting from the beginning

**Challenge TTL rationale:** WebAuthn challenge sessions use a 5-minute TTL (`auth.webauthn_sessions`). This is intentionally short:
- Long-lived challenges increase the window for replay attacks
- 5 minutes is well within the time needed for a user to complete a passkey ceremony
- Expired challenges return a clear error prompting the user to restart the flow
