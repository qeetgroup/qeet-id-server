-- Queries for the domain-verification domain.
-- All queries are static. Error handling for the unique-index violations
-- (uq_tenant_domain, uq_verified_domain) stays in the service layer via
-- strings.Contains checks preserved in domainverify.go.

-- name: InsertDomain :one
INSERT INTO tenant.domains (tenant_id, domain, verification_token)
VALUES ($1, $2, $3)
RETURNING id, domain, verification_token, verified_at, created_at;

-- name: ListDomains :many
SELECT id, domain, verification_token, verified_at, created_at
FROM tenant.domains WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: GetDomainForVerify :one
SELECT id, domain, verification_token, verified_at, created_at
FROM tenant.domains WHERE id = $1 AND tenant_id = $2;

-- name: MarkDomainVerified :one
UPDATE tenant.domains SET verified_at = NOW()
WHERE id = $1 AND tenant_id = $2
RETURNING id, domain, verification_token, verified_at, created_at;

-- name: DeleteDomain :execrows
DELETE FROM tenant.domains WHERE id = $1 AND tenant_id = $2;

-- EmailDomainManager returns the organisation managing accounts on @domain:
-- the one that verified it, or the closest domain above it, with that
-- domain's switches. @domain is lower-case.
-- name: EmailDomainManager :one
SELECT d.tenant_id, d.sso_enabled, d.jit_enabled
FROM tenant.domains d
WHERE d.verified_at IS NOT NULL
  AND (lower(d.domain) = @domain::text
       OR right(@domain::text, length(d.domain) + 1) = '.' || lower(d.domain))
ORDER BY length(d.domain) DESC
LIMIT 1;

-- name: GetLoginDomainCheck :one
SELECT host, checked_at, result FROM tenant.login_domain_checks WHERE tenant_id = @tenant_id;

-- name: SaveLoginDomainCheck :exec
INSERT INTO tenant.login_domain_checks (tenant_id, host, checked_at, result)
VALUES (@tenant_id, @host, @checked_at, @result)
ON CONFLICT (tenant_id) DO UPDATE
SET host = EXCLUDED.host, checked_at = EXCLUDED.checked_at, result = EXCLUDED.result;

-- name: GetCaptureExemption :one
-- Whether the organisation has an active SAML or LDAP connection, and whether
-- the address keeps its own sign-in methods there: its account is a
-- break-glass member, or an administrator single sign-on can't sign in (an
-- administrator is never adopted by address, so only a home account linked to
-- an active connection can). Every branch runs for every address.
WITH account AS (
    SELECT u.id, u.tenant_id FROM "user".users u
    WHERE lower(u.email) = lower(sqlc.arg(email)::text) AND u.deleted_at IS NULL
      AND (u.tenant_id = sqlc.arg(tenant_id)::uuid OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = sqlc.arg(tenant_id)::uuid))
)
SELECT
    (EXISTS (SELECT 1 FROM tenant.saml_connections s WHERE s.tenant_id = sqlc.arg(tenant_id)::uuid AND s.status = 'active')
     OR EXISTS (SELECT 1 FROM tenant.ldap_connections l WHERE l.tenant_id = sqlc.arg(tenant_id)::uuid AND l.status = 'active'))::boolean AS sso,
    EXISTS (
        SELECT 1 FROM account a
        JOIN tenant.break_glass_members b ON b.user_id = a.id AND b.tenant_id = sqlc.arg(tenant_id)::uuid
    )::boolean AS break_glass,
    EXISTS (
        SELECT 1 FROM account a
        WHERE (EXISTS (
                  SELECT 1 FROM rbac.user_roles ur
                  JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.tenant_id = ur.tenant_id
                  LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
                  LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
                  WHERE ur.user_id = a.id AND ur.tenant_id = sqlc.arg(tenant_id)::uuid
                    AND ((ro.is_system AND ro.name = 'owner') OR p.key = ANY(sqlc.arg(admin_permissions)::text[])))
               OR EXISTS (
                  SELECT 1 FROM tenant.group_members gm
                  JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
                  JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id
                  LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
                  LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
                  WHERE gm.user_id = a.id AND gm.tenant_id = sqlc.arg(tenant_id)::uuid
                    AND ((ro.is_system AND ro.name = 'owner') OR p.key = ANY(sqlc.arg(admin_permissions)::text[]))))
          AND NOT (a.tenant_id IS NOT DISTINCT FROM sqlc.arg(tenant_id)::uuid AND EXISTS (
                  SELECT 1 FROM "user".external_identities ei
                  WHERE ei.user_id = a.id AND ei.tenant_id = sqlc.arg(tenant_id)::uuid
                    AND (EXISTS (SELECT 1 FROM tenant.saml_connections s
                                 WHERE s.id = ei.connection_id AND s.tenant_id = ei.tenant_id AND ei.provider = 'saml' AND s.status = 'active')
                         OR EXISTS (SELECT 1 FROM tenant.ldap_connections l
                                    WHERE l.id = ei.connection_id AND l.tenant_id = ei.tenant_id AND ei.provider = 'ldap' AND l.status = 'active'))))
    )::boolean AS unadoptable_admin;

-- name: ListActiveSSOConnections :many
SELECT s.id, 'saml'::text AS protocol, s.name FROM tenant.saml_connections s
WHERE s.tenant_id = sqlc.arg(tenant_id)::uuid AND s.status = 'active'
UNION ALL
SELECT l.id, 'ldap'::text AS protocol, l.name FROM tenant.ldap_connections l
WHERE l.tenant_id = sqlc.arg(tenant_id)::uuid AND l.status = 'active'
ORDER BY protocol DESC, name;

-- name: ListBreakGlassMembers :many
SELECT b.user_id, u.email, u.display_name, b.created_by, b.created_at
FROM tenant.break_glass_members b
JOIN "user".users u ON u.id = b.user_id
WHERE b.tenant_id = $1
ORDER BY lower(u.email);

-- name: IsTenantMember :one
-- A member: the organisation is the account's home, or the account holds one
-- of its roles.
SELECT EXISTS (
    SELECT 1 FROM "user".users u
    WHERE u.id = sqlc.arg(user_id) AND u.deleted_at IS NULL
      AND (u.tenant_id = sqlc.arg(tenant_id)::uuid OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = sqlc.arg(tenant_id)::uuid))
)::boolean;

-- name: InsertBreakGlassMember :execrows
INSERT INTO tenant.break_glass_members (tenant_id, user_id, created_by)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- name: DeleteBreakGlassMember :execrows
DELETE FROM tenant.break_glass_members WHERE tenant_id = $1 AND user_id = $2;
