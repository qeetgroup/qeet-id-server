-- Queries for the domain-verification domain.
-- All queries are static. Error handling for the unique-index violations
-- (uq_organization_domain, uq_verified_domain) stays in the service layer via
-- strings.Contains checks preserved in domainverify.go.

-- name: InsertDomain :one
INSERT INTO organization.domains (organization_id, domain, verification_token)
VALUES ($1, $2, $3)
RETURNING id, domain, verification_token, verified_at, created_at;

-- ListDomains lists an organization's domains with their switches and the
-- outcome of their last check.
-- name: ListDomains :many
SELECT id, domain, verification_token, verified_at, created_at,
       last_checked_at, COALESCE(last_error, '')::text AS last_error, sso_enabled, jit_enabled
FROM organization.domains
WHERE organization_id = $1
ORDER BY domain;

-- UpdateDomainSettings sets the switches given; a NULL one keeps its value.
-- name: UpdateDomainSettings :one
UPDATE organization.domains SET
    sso_enabled = COALESCE(sqlc.narg('sso_enabled')::boolean, sso_enabled),
    jit_enabled = COALESCE(sqlc.narg('jit_enabled')::boolean, jit_enabled)
WHERE id = @id AND organization_id = @organization_id
RETURNING id, domain, verification_token, verified_at, created_at,
          last_checked_at, COALESCE(last_error, '')::text AS last_error, sso_enabled, jit_enabled;

-- RecordDomainCheck stamps a verification attempt: its failure, or NULL for
-- one that found the record.
-- name: RecordDomainCheck :exec
UPDATE organization.domains SET last_checked_at = NOW(), last_error = sqlc.narg('last_error')
WHERE id = @id AND organization_id = @organization_id;

-- name: GetDomainForVerify :one
SELECT id, domain, verification_token, verified_at, created_at
FROM organization.domains WHERE id = $1 AND organization_id = $2;

-- name: MarkDomainVerified :one
UPDATE organization.domains SET verified_at = NOW()
WHERE id = $1 AND organization_id = $2
RETURNING id, domain, verification_token, verified_at, created_at;

-- name: DeleteDomain :execrows
DELETE FROM organization.domains WHERE id = $1 AND organization_id = $2;

-- EmailDomainManager returns the organization managing accounts on @domain:
-- the one that verified it, or the closest domain above it, with that
-- domain's switches. @domain is lower-case.
-- name: EmailDomainManager :one
SELECT d.organization_id, d.sso_enabled, d.jit_enabled
FROM organization.domains d
WHERE d.verified_at IS NOT NULL
  AND (lower(d.domain) = @domain::text
       OR right(@domain::text, length(d.domain) + 1) = '.' || lower(d.domain))
ORDER BY length(d.domain) DESC
LIMIT 1;

-- name: GetLoginDomainCheck :one
SELECT host, checked_at, result FROM organization.login_domain_checks WHERE organization_id = @organization_id;

-- name: SaveLoginDomainCheck :exec
INSERT INTO organization.login_domain_checks (organization_id, host, checked_at, result)
VALUES (@organization_id, @host, @checked_at, @result)
ON CONFLICT (organization_id) DO UPDATE
SET host = EXCLUDED.host, checked_at = EXCLUDED.checked_at, result = EXCLUDED.result;

-- name: GetCaptureExemption :one
-- Whether the organization has an active SAML, LDAP or OpenID Connect
-- connection, and whether
-- the address keeps its own sign-in methods there: its account is a
-- break-glass member, or an administrator single sign-on can't sign in (an
-- administrator is never adopted by address, so only a home account linked to
-- an active connection can). Every branch runs for every address.
WITH account AS (
    SELECT u.id, u.organization_id FROM account.users u
    WHERE lower(u.email) = lower(sqlc.arg(email)::text) AND u.deleted_at IS NULL
      AND (u.organization_id = sqlc.arg(organization_id)::uuid OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id = sqlc.arg(organization_id)::uuid))
)
SELECT
    (EXISTS (SELECT 1 FROM organization.saml_connections s WHERE s.organization_id = sqlc.arg(organization_id)::uuid AND s.status = 'active')
     OR EXISTS (SELECT 1 FROM organization.ldap_connections l WHERE l.organization_id = sqlc.arg(organization_id)::uuid AND l.status = 'active')
     OR EXISTS (SELECT 1 FROM organization.oidc_connections o WHERE o.organization_id = sqlc.arg(organization_id)::uuid AND o.status = 'active'))::boolean AS sso,
    EXISTS (
        SELECT 1 FROM account a
        JOIN organization.break_glass_members b ON b.user_id = a.id AND b.organization_id = sqlc.arg(organization_id)::uuid
    )::boolean AS break_glass,
    EXISTS (
        SELECT 1 FROM account a
        WHERE (EXISTS (
                  SELECT 1 FROM rbac.user_roles ur
                  JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id
                  LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
                  LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
                  WHERE ur.user_id = a.id AND ur.organization_id = sqlc.arg(organization_id)::uuid
                    AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(sqlc.arg(member_permissions)::text[])))))
               OR EXISTS (
                  SELECT 1 FROM organization.group_members gm
                  JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
                  JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
                  LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
                  LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
                  WHERE gm.user_id = a.id AND gm.organization_id = sqlc.arg(organization_id)::uuid
                    AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(sqlc.arg(member_permissions)::text[]))))))
          AND NOT (a.organization_id IS NOT DISTINCT FROM sqlc.arg(organization_id)::uuid AND EXISTS (
                  SELECT 1 FROM account.external_identities ei
                  WHERE ei.user_id = a.id AND ei.organization_id = sqlc.arg(organization_id)::uuid
                    AND (EXISTS (SELECT 1 FROM organization.saml_connections s
                                 WHERE s.id = ei.connection_id AND s.organization_id = ei.organization_id AND ei.provider = 'saml' AND s.status = 'active')
                         OR EXISTS (SELECT 1 FROM organization.ldap_connections l
                                    WHERE l.id = ei.connection_id AND l.organization_id = ei.organization_id AND ei.provider = 'ldap' AND l.status = 'active')
                         OR EXISTS (SELECT 1 FROM organization.oidc_connections o
                                    WHERE o.id = ei.connection_id AND o.organization_id = ei.organization_id AND ei.provider = 'oidc' AND o.status = 'active'))))
    )::boolean AS unadoptable_admin;

-- name: ListActiveSSOConnections :many
SELECT s.id, 'saml'::text AS protocol, s.name FROM organization.saml_connections s
WHERE s.organization_id = sqlc.arg(organization_id)::uuid AND s.status = 'active'
UNION ALL
SELECT l.id, 'ldap'::text AS protocol, l.name FROM organization.ldap_connections l
WHERE l.organization_id = sqlc.arg(organization_id)::uuid AND l.status = 'active'
UNION ALL
SELECT o.id, 'oidc'::text AS protocol, o.name FROM organization.oidc_connections o
WHERE o.organization_id = sqlc.arg(organization_id)::uuid AND o.status = 'active'
ORDER BY protocol DESC, name;

-- name: OrganizationName :one
-- The name an organization's people know it by, for its sign-in page.
SELECT name FROM organization.organizations WHERE id = @organization_id AND deleted_at IS NULL;

-- name: ListBreakGlassMembers :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT b.user_id, u.email, u.display_name, b.created_by, b.created_at
FROM organization.break_glass_members b
JOIN account.users u ON u.id = b.user_id
WHERE b.organization_id = $1
ORDER BY lower(u.email)
LIMIT 1001;

-- name: IsOrganizationMember :one
-- A member: the organization is the account's home, or the account holds one
-- of its roles.
SELECT EXISTS (
    SELECT 1 FROM account.users u
    WHERE u.id = sqlc.arg(user_id) AND u.deleted_at IS NULL
      AND (u.organization_id = sqlc.arg(organization_id)::uuid OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id = sqlc.arg(organization_id)::uuid))
)::boolean;

-- name: InsertBreakGlassMember :execrows
INSERT INTO organization.break_glass_members (organization_id, user_id, created_by)
VALUES ($1, $2, $3)
ON CONFLICT (organization_id, user_id) DO NOTHING;

-- name: DeleteBreakGlassMember :execrows
DELETE FROM organization.break_glass_members WHERE organization_id = $1 AND user_id = $2;

-- LoginHost is the organization's custom login hostname as stored; '' for none.
-- name: LoginHost :one
SELECT COALESCE(custom_domain, '')::text FROM organization.branding WHERE organization_id = $1;
