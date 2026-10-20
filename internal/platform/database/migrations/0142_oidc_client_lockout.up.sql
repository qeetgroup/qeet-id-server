-- 0142_oidc_client_lockout — count wrong application secrets and lock out.
--
-- A confidential application proves itself with its secret on every endpoint
-- that takes one (code exchange, refresh, token exchange, device and
-- backchannel requests, revocation, introspection). Nothing counted a wrong
-- secret, so guessing one at volume was unlimited and invisible. One row per
-- application that has failed recently: failures within the current window,
-- and the lockout that crossing the threshold starts. Deleted on a successful
-- authentication, and with the application.
CREATE TABLE auth.oidc_client_auth_lockouts (
    client_row_id     UUID PRIMARY KEY REFERENCES auth.oidc_clients (id) ON DELETE CASCADE,
    failures          INTEGER     NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failure_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until      TIMESTAMPTZ
);
