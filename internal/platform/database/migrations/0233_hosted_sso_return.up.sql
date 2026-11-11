-- 0233_hosted_sso_return — a SAML or OpenID Connect sign-in started on the hosted login keeps
-- where the browser goes back to (the application's authorize request), so the answer from the
-- identity provider returns there instead of to the console. Absent for a console sign-in.
ALTER TABLE auth.saml_authn_requests ADD COLUMN IF NOT EXISTS return_to TEXT;
ALTER TABLE auth.oidc_connection_states ADD COLUMN IF NOT EXISTS return_to TEXT;
