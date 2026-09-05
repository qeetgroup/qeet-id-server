# JWT signing-key rotation

Qeet ID has no runtime signing-key mutation endpoint. API replicas converge on
the shared `platform.jwt_signing_keys` registry. Candidate and active private
keys are envelope-encrypted with the deployment's configured KMS/static data
key; retired rows retain public material only and carry an explicit
`retire_at` deadline.

`JWT_SIGNING_KEY` registers key material as a candidate. On an empty registry,
the first configured key becomes active automatically. On a populated registry,
`JWT_ACTIVATE_SIGNING_KEY=true` is required to promote a different candidate.
This prevents a stale replica from reverting the active key during a rolling
deployment. Replicas refresh the registry every
`JWT_SIGNING_KEY_REFRESH_INTERVAL` (default 5 seconds).

## Zero-downtime rotation

1. Generate the next P-256 private key in the deployment secret manager. Never
   generate or return private key material through an application endpoint.
2. **Prepare:** deploy every replica with the next key in `JWT_SIGNING_KEY` and
   `JWT_ACTIVATE_SIGNING_KEY=false`. The active database key continues signing;
   the next public key appears as `candidate` in `/v1/oidc/signing-keys` and in
   JWKS on every replica after refresh.
3. Verify every replica publishes both KIDs. Do not activate until all replicas
   use the same KMS/static envelope key and can read the candidate.
4. **Activate:** set `JWT_ACTIVATE_SIGNING_KEY=true`. The first reconciler
   atomically promotes the candidate and retires the prior active key with
   `retire_at = now + JWT_SIGNING_KEY_RETIRE_GRACE`; all replicas switch their
   signing snapshot after refresh. Reset the activation flag to `false` after
   convergence.
5. Confirm every replica reports the new KID as active and accepts tokens from
   both generations. Restart a replica and repeat the check.
6. **Retire:** no deployment action is needed at the deadline. Each issuer
   snapshot enforces `retire_at` locally, and subsequent refreshes remove the
   expired public key from JWKS. Non-expiring JWT-VCs must be revoked/reissued
   before that deadline or the grace period must cover their intended lifetime.

## What a staged candidate can already do

Between pre-stage and activate, the candidate's **public** key is published in
JWKS and accepted for verification on every replica. That is what makes the
activation step seamless — a replica that has already switched can hand a token
to one that has not — but it means the trusted verification set widens the
moment you pre-stage, not the moment you activate.

Practically: anyone holding the candidate **private** key can mint tokens the
whole fleet accepts, before `JWT_ACTIVATE_SIGNING_KEY` is ever set. Treat
pre-staging as the point at which the new key becomes security-relevant, and
keep the pre-stage window short.

Retired keys are the mirror image: their private material is deleted from the
registry on activation (`private_key_ct = NULL`) and only the public key
survives, until `retire_at` passes.

## Rollback

During the grace period, deploy the prior private key as `JWT_SIGNING_KEY`,
pre-stage it with activation off, then explicitly activate it. The registry
rehydrates that key from deployment configuration, retires the failed key with
a new deadline, and converges every replica. Never add a rotation endpoint.

## Verification

- `go test -race ./internal/platform/crypto/tokens`
- `go test -race -tags=integration ./tests/integration -run SigningKeyRegistry`
- Check `/.well-known/jwks.json` on every replica before and after activation.
- Verify one token from each signing generation against every replica.
