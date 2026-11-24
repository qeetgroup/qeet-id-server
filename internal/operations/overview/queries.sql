-- Queries for the organization overview: each area's set-up state and counts,
-- each read only for a caller who may read that area.

-- SingleSignOn counts the organization's SAML, LDAP and OpenID Connect
-- connections (all, and active), its social providers (all, and turned on) and
-- its SCIM tokens still accepted.
-- name: SingleSignOn :one
SELECT
  (SELECT count(*) FROM organization.saml_connections c WHERE c.organization_id = @organization_id::uuid)::int AS saml_total,
  (SELECT count(*) FROM organization.saml_connections c WHERE c.organization_id = @organization_id::uuid AND c.status = 'active')::int AS saml_active,
  (SELECT count(*) FROM organization.ldap_connections c WHERE c.organization_id = @organization_id::uuid)::int AS ldap_total,
  (SELECT count(*) FROM organization.ldap_connections c WHERE c.organization_id = @organization_id::uuid AND c.status = 'active')::int AS ldap_active,
  (SELECT count(*) FROM organization.oidc_connections c WHERE c.organization_id = @organization_id::uuid)::int AS oidc_total,
  (SELECT count(*) FROM organization.oidc_connections c WHERE c.organization_id = @organization_id::uuid AND c.status = 'active')::int AS oidc_active,
  (SELECT count(*) FROM organization.social_providers p WHERE p.organization_id = @organization_id::uuid)::int AS social_total,
  (SELECT count(*) FROM organization.social_providers p WHERE p.organization_id = @organization_id::uuid AND p.enabled)::int AS social_enabled,
  (SELECT count(*) FROM organization.scim_tokens s WHERE s.organization_id = @organization_id::uuid AND s.revoked_at IS NULL
     AND (s.expires_at IS NULL OR s.expires_at > NOW()))::int AS scim_tokens_active;

-- Applications counts the organization's OpenID Connect applications, the SAML
-- service providers it signs people in to (all, and active), and the
-- applications' live grants and the people holding them.
-- name: Applications :one
SELECT
  (SELECT count(*) FROM auth.oidc_clients c WHERE c.organization_id = @organization_id::uuid)::int AS oidc_clients,
  (SELECT count(*) FROM organization.saml_service_providers p WHERE p.organization_id = @organization_id::uuid)::int AS saml_providers_total,
  (SELECT count(*) FROM organization.saml_service_providers p WHERE p.organization_id = @organization_id::uuid AND p.status = 'active')::int AS saml_providers_active,
  (SELECT count(*) FROM auth.oidc_refresh_tokens t WHERE t.organization_id = @organization_id::uuid
     AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW())::int AS grants_active,
  (SELECT count(DISTINCT t.user_id) FROM auth.oidc_refresh_tokens t WHERE t.organization_id = @organization_id::uuid
     AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW())::int AS grant_holders;

-- Domains counts the organization's domains: all, verified, and verified with
-- single sign-on required.
-- name: Domains :one
SELECT count(*)::int AS total,
       count(*) FILTER (WHERE d.verified_at IS NOT NULL)::int AS verified,
       count(*) FILTER (WHERE d.verified_at IS NOT NULL AND d.sso_enabled)::int AS sso_required
FROM organization.domains d
WHERE d.organization_id = @organization_id::uuid;

-- DirectoryErrors counts the organization's directory errors of the last 7 days
-- still open, as its directory errors page shows them by default.
-- name: DirectoryErrors :one
SELECT count(*)::int AS open
FROM organization.directory_events e
WHERE e.organization_id = @organization_id::uuid AND e.started_at >= NOW() - INTERVAL '7 days'
  AND e.status <> 'success' AND e.status <> 'warning' AND e.resolution = 'open';

-- RememberedDevices counts the devices remembered in the organization that
-- still skip the second step, and the people they belong to.
-- name: RememberedDevices :one
SELECT count(*)::int AS devices, count(DISTINCT d.user_id)::int AS people
FROM auth.trusted_devices d
WHERE d.organization_id = @organization_id::uuid AND d.expires_at > NOW();

-- APIKeys counts the organization's API keys still accepted: not revoked, not
-- expired.
-- name: APIKeys :one
SELECT count(*)::int AS active
FROM auth.api_keys k
WHERE k.organization_id = @organization_id::uuid AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW());

-- Webhooks counts the organization's webhook subscriptions: all, those turned
-- on, and those turned on whose deliveries are failing.
-- name: Webhooks :one
SELECT count(*)::int AS total,
       count(*) FILTER (WHERE w.disabled_at IS NULL)::int AS enabled,
       count(*) FILTER (WHERE w.disabled_at IS NULL AND w.failing_since IS NOT NULL)::int AS failing
FROM organization.webhook_subscriptions w
WHERE w.organization_id = @organization_id::uuid;

-- MFAEnforcement is who the organization's security policy makes use a second
-- factor; optional when it has saved none.
-- name: MFAEnforcement :one
SELECT COALESCE((SELECT p.mfa_enforcement FROM organization.security_policies p WHERE p.organization_id = @organization_id::uuid),
                'optional')::text AS mfa_enforcement;

-- AccessPolicies counts the organization's attribute-based access policies:
-- all, and those turned on; and its open security anomalies.
-- name: AccessPolicies :one
SELECT
  (SELECT count(*) FROM auth.abac_policies p WHERE p.organization_id = @organization_id::uuid)::int AS abac_total,
  (SELECT count(*) FROM auth.abac_policies p WHERE p.organization_id = @organization_id::uuid AND p.enabled)::int AS abac_enabled,
  (SELECT count(*) FROM auth.security_events e WHERE e.organization_id = @organization_id::uuid AND e.status = 'open')::int AS open_anomalies;

-- PendingInvitations counts the organization's invitations still waiting to be
-- answered: pending and not expired.
-- name: PendingInvitations :one
SELECT count(*)::int AS pending
FROM organization.invites i
WHERE i.organization_id = @organization_id::uuid AND i.status = 'pending' AND i.expires_at > NOW();

-- Billing is the organization's plan, and its subscription when it has one.
-- name: Billing :one
SELECT o.plan, s.status AS subscription_status, s.trial_end, s.current_period_end,
       COALESCE(s.cancel_at_period_end, FALSE)::bool AS cancel_at_period_end
FROM organization.organizations o
LEFT JOIN organization.subscriptions s ON s.organization_id = o.id
WHERE o.id = @organization_id::uuid;
