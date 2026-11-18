-- Queries for the saml domain.
-- Covers both saml.go (SP-side Service) and idp.go (IdP-side IdP struct).

-- ==========================================================================
-- SP-side: external IdP connections (saml.go)
-- ==========================================================================

-- name: InsertSamlConnection :one
INSERT INTO organization.saml_connections
    (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
VALUES (@organization_id, @name, @idp_entity_id, @idp_sso_url, @idp_certificate, @email_attribute, @name_attribute, @status)
RETURNING id, organization_id, name, idp_entity_id, idp_sso_url, idp_certificate,
          email_attribute, name_attribute, status, created_at, updated_at, last_login_at;

-- name: ListSamlConnections :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM organization.saml_connections WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetSamlConnection :one
SELECT id, organization_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id;

-- name: GetSamlConnectionByID :one
SELECT id, organization_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM organization.saml_connections WHERE id = @id;

-- name: UpdateSamlConnection :one
UPDATE organization.saml_connections SET
    name            = COALESCE(sqlc.narg('name'), name),
    idp_entity_id   = COALESCE(sqlc.narg('idp_entity_id'), idp_entity_id),
    idp_sso_url     = COALESCE(sqlc.narg('idp_sso_url'), idp_sso_url),
    idp_certificate = COALESCE(sqlc.narg('idp_certificate'), idp_certificate),
    email_attribute = COALESCE(sqlc.narg('email_attribute'), email_attribute),
    name_attribute  = COALESCE(sqlc.narg('name_attribute'), name_attribute),
    status          = COALESCE(sqlc.narg('status'), status),
    updated_at      = NOW()
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, idp_entity_id, idp_sso_url, idp_certificate,
          email_attribute, name_attribute, status, created_at, updated_at, last_login_at;

-- name: DeleteSamlConnection :execrows
DELETE FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id;

-- name: TouchSamlLastLogin :exec
UPDATE organization.saml_connections SET last_login_at = NOW() WHERE id = @id;

-- The groups attribute isn't in the connection queries above, so it is read
-- and written on its own.

-- name: GetSamlGroupsAttribute :one
SELECT groups_attribute FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id;

-- name: ListSamlGroupsAttributes :many
SELECT id, groups_attribute FROM organization.saml_connections WHERE organization_id = @organization_id;

-- name: SetSamlGroupsAttribute :exec
UPDATE organization.saml_connections SET groups_attribute = @groups_attribute, updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- Nor is allow_idp_initiated, the opt-in to unsolicited assertions.

-- name: ListSamlIdPInitiatedFlags :many
SELECT id, allow_idp_initiated FROM organization.saml_connections WHERE organization_id = @organization_id;

-- name: GetSamlAllowIdPInitiated :one
SELECT allow_idp_initiated FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id;

-- name: SamlAllowsIdPInitiated :one
SELECT allow_idp_initiated FROM organization.saml_connections WHERE id = @id;

-- name: SetSamlAllowIdPInitiated :exec
UPDATE organization.saml_connections SET allow_idp_initiated = @allow_idp_initiated, updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- ==========================================================================
-- SP-side: pending AuthnRequests and replay reservations (saml.go)
-- ==========================================================================

-- name: PurgeExpiredSamlAuthnRequests :exec
DELETE FROM auth.saml_authn_requests WHERE expires_at <= NOW();

-- name: InsertSamlAuthnRequest :exec
-- An empty return_to (a console sign-in) is stored as NULL.
INSERT INTO auth.saml_authn_requests (request_id, connection_id, expires_at, return_to)
VALUES (@request_id, @connection_id, @expires_at, NULLIF(@return_to::text, ''));

-- name: HostedSamlReturn :one
-- The return_to of the latest pending sign-in, among request_ids, that the
-- hosted login began on the connection.
SELECT return_to::text FROM auth.saml_authn_requests
WHERE connection_id = @connection_id AND request_id = ANY(@request_ids::text[])
  AND return_to IS NOT NULL AND expires_at > NOW()
ORDER BY expires_at DESC
LIMIT 1;

-- name: ConsumeSamlAuthnRequest :one
DELETE FROM auth.saml_authn_requests
WHERE request_id = @request_id AND connection_id = @connection_id AND expires_at > NOW()
RETURNING return_to;

-- name: PurgeExpiredSamlReplayIDs :exec
DELETE FROM auth.saml_replay_ids WHERE expires_at <= NOW();

-- name: ReserveSamlReplayID :execrows
-- No row when the ID was already presented: a replay.
INSERT INTO auth.saml_replay_ids (connection_id, kind, saml_id, expires_at)
VALUES (@connection_id, @kind, @saml_id, @expires_at)
ON CONFLICT DO NOTHING;

-- ==========================================================================
-- SP-side: test sign-ins (testsignin.go)
-- ==========================================================================

-- name: InsertSamlTestSignIn :one
INSERT INTO auth.saml_test_sign_ins (connection_id, request_id, return_url, expires_at)
VALUES (@connection_id, @request_id, @return_url, @expires_at)
RETURNING id, expires_at, created_at;

-- name: GetSamlTestSignIn :one
SELECT t.id, t.connection_id, t.status, t.result, t.expires_at, t.created_at, t.completed_at
FROM auth.saml_test_sign_ins t
JOIN organization.saml_connections c ON c.id = t.connection_id
WHERE t.id = @id AND t.connection_id = @connection_id AND c.organization_id = @organization_id;

-- name: GetSamlTestSignInByRequest :one
SELECT id, return_url FROM auth.saml_test_sign_ins
WHERE connection_id = @connection_id AND request_id = @request_id;

-- name: FinishSamlTestSignIn :exec
-- Once, while the test still waits.
UPDATE auth.saml_test_sign_ins SET status = @status, result = @result, completed_at = NOW()
WHERE id = @id AND status = 'pending' AND expires_at > NOW();

-- ==========================================================================
-- SP-side: the IdP signing certificates a connection trusts (certificates.go)
-- ==========================================================================

-- name: LockSamlConnection :one
SELECT id FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id FOR UPDATE;

-- name: ListSamlCertificates :many
SELECT id, organization_id, connection_id, certificate, source, created_at
FROM organization.saml_connection_certificates
WHERE connection_id = @connection_id AND organization_id = @organization_id
ORDER BY created_at, id;

-- name: ListSamlCertificatesForOrganization :many
SELECT id, organization_id, connection_id, certificate, source, created_at
FROM organization.saml_connection_certificates
WHERE organization_id = @organization_id
ORDER BY created_at, id;

-- name: InsertSamlCertificate :one
INSERT INTO organization.saml_connection_certificates (organization_id, connection_id, certificate, source)
VALUES (@organization_id, @connection_id, @certificate, @source)
RETURNING id, organization_id, connection_id, certificate, source, created_at;

-- name: DeleteSamlCertificate :exec
DELETE FROM organization.saml_connection_certificates
WHERE id = @id AND connection_id = @connection_id AND organization_id = @organization_id;

-- name: DeleteSamlCertificates :exec
DELETE FROM organization.saml_connection_certificates
WHERE connection_id = @connection_id AND organization_id = @organization_id;

-- name: SetSamlCertificateSource :exec
UPDATE organization.saml_connection_certificates SET source = @source
WHERE id = @id AND organization_id = @organization_id;

-- name: SyncSamlPrimaryCertificate :exec
UPDATE organization.saml_connections c SET
    idp_certificate = (
        SELECT k.certificate FROM organization.saml_connection_certificates k
        WHERE k.connection_id = c.id AND k.organization_id = c.organization_id
        ORDER BY k.created_at, k.id LIMIT 1
    ),
    updated_at = NOW()
WHERE c.id = @id AND c.organization_id = @organization_id;

-- ==========================================================================
-- SP-side: a connection's IdP metadata (metadata.go)
-- ==========================================================================

-- name: GetSamlMetadataSource :one
SELECT metadata_url, metadata_refreshed_at, metadata_error
FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id;

-- name: ListSamlMetadataSources :many
SELECT id, metadata_url, metadata_refreshed_at, metadata_error
FROM organization.saml_connections WHERE organization_id = @organization_id;

-- name: LockSamlMetadataSource :one
SELECT idp_entity_id, idp_sso_url, metadata_url FROM organization.saml_connections
WHERE id = @id AND organization_id = @organization_id FOR UPDATE;

-- name: SetSamlIdPFromMetadata :exec
UPDATE organization.saml_connections SET
    idp_sso_url           = @idp_sso_url,
    metadata_url          = sqlc.narg('metadata_url'),
    metadata_checked_at   = NOW(),
    metadata_refreshed_at = NOW(),
    metadata_error        = NULL,
    updated_at            = CASE WHEN idp_sso_url <> @idp_sso_url THEN NOW() ELSE updated_at END
WHERE id = @id AND organization_id = @organization_id;

-- name: SetSamlMetadataError :exec
UPDATE organization.saml_connections SET metadata_checked_at = NOW(), metadata_error = @metadata_error
WHERE id = @id AND organization_id = @organization_id;

-- name: ListSamlMetadataDue :many
SELECT id, organization_id, metadata_url::text AS metadata_url FROM organization.saml_connections
WHERE metadata_url IS NOT NULL AND (metadata_checked_at IS NULL OR metadata_checked_at < @checked_before)
ORDER BY metadata_checked_at NULLS FIRST, id
LIMIT @max_rows;

-- ==========================================================================
-- SP-side: the key pair a connection's IdP encrypts assertions to (encryption.go)
-- ==========================================================================

-- name: GetSamlConnectionKey :one
SELECT certificate, key_ct, key_nonce FROM organization.saml_connection_keys
WHERE connection_id = @connection_id AND organization_id = @organization_id;

-- name: InsertSamlConnectionKey :exec
INSERT INTO organization.saml_connection_keys (connection_id, organization_id, certificate, key_ct, key_nonce)
VALUES (@connection_id, @organization_id, @certificate, @key_ct, @key_nonce)
ON CONFLICT (connection_id) DO NOTHING;

-- ==========================================================================
-- IdP-side: Qeet as SAML provider (idp.go)
-- ==========================================================================

-- name: InsertSamlSP :one
INSERT INTO organization.saml_service_providers
    (organization_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status,
     attributes, assignment_required, require_signed_requests, encrypt_assertions)
VALUES (@organization_id, @name, @entity_id, @acs_url, @name_id_format, @name_id_attribute, @certificate, @status,
        @attributes, @assignment_required, @require_signed_requests, @encrypt_assertions)
RETURNING id, organization_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes, assignment_required, require_signed_requests, encrypt_assertions;

-- name: ListSamlSPs :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM organization.saml_service_providers WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetSamlSP :one
SELECT id, organization_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM organization.saml_service_providers WHERE id = @id AND organization_id = @organization_id;

-- GetSamlSPForUpdate reads a service provider and holds it until the
-- transaction ends, so a change is checked against what it changes.
-- name: GetSamlSPForUpdate :one
SELECT id, organization_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM organization.saml_service_providers WHERE id = @id AND organization_id = @organization_id
FOR UPDATE;

-- name: GetSamlSPByEntityID :one
SELECT id, organization_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM organization.saml_service_providers
WHERE organization_id = @organization_id AND entity_id = @entity_id AND status <> 'disabled';

-- name: IsOrganizationActive :one
SELECT EXISTS (
    SELECT 1 FROM organization.organizations WHERE id = @id AND status = 'active' AND deleted_at IS NULL
);

-- name: UpdateSamlSP :one
UPDATE organization.saml_service_providers SET
    name                = COALESCE(sqlc.narg('name'), name),
    entity_id           = COALESCE(sqlc.narg('entity_id'), entity_id),
    acs_url             = COALESCE(sqlc.narg('acs_url'), acs_url),
    name_id_format      = COALESCE(sqlc.narg('name_id_format'), name_id_format),
    name_id_attribute   = COALESCE(sqlc.narg('name_id_attribute'), name_id_attribute),
    certificate         = COALESCE(sqlc.narg('certificate'), certificate),
    status              = COALESCE(sqlc.narg('status'), status),
    attributes          = COALESCE(sqlc.narg('attributes'), attributes),
    assignment_required = COALESCE(sqlc.narg('assignment_required'), assignment_required),
    require_signed_requests = COALESCE(sqlc.narg('require_signed_requests'), require_signed_requests),
    encrypt_assertions  = COALESCE(sqlc.narg('encrypt_assertions'), encrypt_assertions),
    updated_at          = NOW()
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes, assignment_required, require_signed_requests, encrypt_assertions;

-- name: DeleteSamlSP :execrows
DELETE FROM organization.saml_service_providers WHERE id = @id AND organization_id = @organization_id;

-- name: TouchSamlSPLastLogin :exec
UPDATE organization.saml_service_providers SET last_login_at = NOW() WHERE id = @id;

-- name: GetUserForIdP :one
SELECT email, display_name, organization_id, status, metadata FROM account.users WHERE id = @id AND deleted_at IS NULL;

-- ==========================================================================
-- IdP-side: what an assertion says about a person (idp_attributes.go)
-- ==========================================================================

-- GetIdPNameParts is a person's given and family name from their
-- organization's directory profiles, the most recently updated one naming each.
-- name: GetIdPNameParts :one
SELECT COALESCE((SELECT p.profile->>'first_name' FROM organization.directory_profiles p
                 WHERE p.organization_id = @organization_id AND p.user_id = @user_id
                   AND jsonb_typeof(p.profile->'first_name') = 'string'
                 ORDER BY p.updated_at DESC LIMIT 1), '')::text AS given_name,
       COALESCE((SELECT p.profile->>'last_name' FROM organization.directory_profiles p
                 WHERE p.organization_id = @organization_id AND p.user_id = @user_id
                   AND jsonb_typeof(p.profile->'last_name') = 'string'
                 ORDER BY p.updated_at DESC LIMIT 1), '')::text AS family_name;

-- name: ListIdPUserGroupNames :many
SELECT g.name
FROM organization.group_members gm
JOIN organization.groups g ON g.id = gm.group_id AND g.organization_id = gm.organization_id
WHERE gm.organization_id = @organization_id AND gm.user_id = @user_id
ORDER BY g.name;

-- ListIdPUserRoleNames is the names of the roles a person holds in the
-- organization, directly or through a group.
-- name: ListIdPUserRoleNames :many
SELECT DISTINCT ro.name
FROM rbac.roles ro
WHERE ro.organization_id = @organization_id AND ro.id IN (
    SELECT ur.role_id FROM rbac.user_roles ur
    WHERE ur.organization_id = @organization_id AND ur.user_id = @user_id
    UNION
    SELECT gr.role_id FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    WHERE gm.organization_id = @organization_id AND gm.user_id = @user_id
)
ORDER BY ro.name;

-- name: GetSamlPersistentID :one
SELECT name_id FROM organization.saml_idp_persistent_ids
WHERE organization_id = @organization_id AND sp_id = @sp_id AND user_id = @user_id;

-- InsertSamlPersistentID keeps name_id as the person's persistent NameID at
-- the service provider, or returns the one another sign-in kept first.
-- name: InsertSamlPersistentID :one
INSERT INTO organization.saml_idp_persistent_ids (organization_id, sp_id, user_id, name_id)
VALUES (@organization_id, @sp_id, @user_id, @name_id)
ON CONFLICT (organization_id, sp_id, user_id) DO UPDATE SET name_id = saml_idp_persistent_ids.name_id
RETURNING name_id;

-- ==========================================================================
-- IdP-side: who may sign in to a service provider (idp_assignment.go)
-- ==========================================================================

-- IsAssignedToSamlSP reports whether a person is assigned to the service
-- provider, themselves or through a group they belong to.
-- name: IsAssignedToSamlSP :one
SELECT (EXISTS (
    SELECT 1 FROM organization.saml_sp_user_assignments ua
    WHERE ua.organization_id = @organization_id AND ua.sp_id = @sp_id AND ua.user_id = @user_id
) OR EXISTS (
    SELECT 1 FROM organization.saml_sp_group_assignments ga
    JOIN organization.group_members gm ON gm.group_id = ga.group_id AND gm.organization_id = ga.organization_id
    WHERE ga.organization_id = @organization_id AND ga.sp_id = @sp_id AND gm.user_id = @user_id
))::bool AS assigned;

-- IsSamlAssignableUser reports whether the organization is the account's home,
-- the only people its service providers sign in.
-- name: IsSamlAssignableUser :one
SELECT EXISTS (
    SELECT 1 FROM account.users WHERE id = @user_id AND organization_id = @organization_id AND deleted_at IS NULL
)::bool;

-- name: IsSamlAssignableGroup :one
SELECT EXISTS (
    SELECT 1 FROM organization.groups WHERE id = @group_id AND organization_id = @organization_id
)::bool;

-- name: ListSamlSPUserAssignments :many
SELECT a.user_id, u.email, u.display_name, a.assigned_at, a.assigned_by
FROM organization.saml_sp_user_assignments a
JOIN account.users u ON u.id = a.user_id
WHERE a.organization_id = @organization_id AND a.sp_id = @sp_id
ORDER BY a.assigned_at, a.user_id;

-- name: ListSamlSPGroupAssignments :many
SELECT a.group_id, g.name, a.assigned_at, a.assigned_by
FROM organization.saml_sp_group_assignments a
JOIN organization.groups g ON g.id = a.group_id AND g.organization_id = a.organization_id
WHERE a.organization_id = @organization_id AND a.sp_id = @sp_id
ORDER BY a.assigned_at, a.group_id;

-- name: InsertSamlSPUserAssignment :execrows
INSERT INTO organization.saml_sp_user_assignments (organization_id, sp_id, user_id, assigned_by)
VALUES (@organization_id, @sp_id, @user_id, sqlc.narg('assigned_by'))
ON CONFLICT DO NOTHING;

-- name: DeleteSamlSPUserAssignment :execrows
DELETE FROM organization.saml_sp_user_assignments
WHERE organization_id = @organization_id AND sp_id = @sp_id AND user_id = @user_id;

-- name: InsertSamlSPGroupAssignment :execrows
INSERT INTO organization.saml_sp_group_assignments (organization_id, sp_id, group_id, assigned_by)
VALUES (@organization_id, @sp_id, @group_id, sqlc.narg('assigned_by'))
ON CONFLICT DO NOTHING;

-- name: DeleteSamlSPGroupAssignment :execrows
DELETE FROM organization.saml_sp_group_assignments
WHERE organization_id = @organization_id AND sp_id = @sp_id AND group_id = @group_id;
