-- Queries for the logincode domain: the one-time codes a federated sign-in's
-- callback hands the browser, traded once for a session. All queries are
-- STATIC.

-- name: InsertLoginCode :exec
INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, connection_id, provider, expires_at)
VALUES (@code_hash, @kind, @user_id, sqlc.narg('organization_id')::uuid, sqlc.narg('connection_id')::uuid,
        sqlc.narg('provider')::text, @expires_at);

-- ClaimLoginCode locks a code of kind with whether what issued it still signs
-- people in: 'active', 'draft' or 'disabled', or 'deleted' once it is gone.
-- name: ClaimLoginCode :one
SELECT lc.user_id, lc.organization_id, lc.connection_id, lc.provider, lc.expires_at, lc.used_at,
       COALESCE(CASE lc.kind
           WHEN 'saml' THEN (SELECT c.status FROM organization.saml_connections c
                             WHERE c.organization_id = lc.organization_id AND c.id = lc.connection_id)
           WHEN 'oidc_connection' THEN (SELECT c.status FROM organization.oidc_connections c
                                        WHERE c.organization_id = lc.organization_id AND c.id = lc.connection_id)
           WHEN 'social' THEN (SELECT CASE WHEN p.enabled THEN 'active' ELSE 'disabled' END
                               FROM organization.social_providers p
                               WHERE p.organization_id = lc.organization_id AND p.provider = lc.provider)
           WHEN 'platform_social' THEN 'active'
       END, 'deleted')::text AS issuer_status
FROM auth.login_codes lc
WHERE lc.code_hash = @code_hash AND lc.kind = @kind
FOR UPDATE OF lc;

-- name: SpendLoginCode :exec
UPDATE auth.login_codes SET used_at = NOW()
WHERE code_hash = @code_hash AND organization_id IS NOT DISTINCT FROM sqlc.narg('organization_id')::uuid;
