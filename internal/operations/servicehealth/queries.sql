-- Queries for the service-health domain.

-- EmailHealth counts the organisation's emails of the last hour handed to the
-- provider, and those it failed to take.
-- name: EmailHealth :one
SELECT count(*) FILTER (WHERE status <> 'suppressed')::int AS attempted,
       count(*) FILTER (WHERE status = 'failed')::int AS failed
FROM platform.email_messages
WHERE tenant_id = @tenant_id AND sent_at > NOW() - INTERVAL '1 hour';

-- WebhookHealth counts the organisation's enabled subscriptions, those whose
-- deliveries are failing, and those disabled for failing.
-- name: WebhookHealth :one
SELECT count(*) FILTER (WHERE disabled_at IS NULL)::int AS active,
       count(*) FILTER (WHERE disabled_at IS NULL AND failing_since IS NOT NULL)::int AS failing,
       count(*) FILTER (WHERE disabled_at IS NOT NULL AND disabled_reason = 'failing')::int AS disabled_failing
FROM tenant.webhook_subscriptions
WHERE tenant_id = @tenant_id;

-- DirectoryHealth counts the organisation's active LDAP connections and live
-- SCIM tokens, and its failed directory operations of the last day still open.
-- name: DirectoryHealth :one
SELECT (SELECT count(*) FROM tenant.ldap_connections l WHERE l.tenant_id = @tenant_id AND l.status = 'active')::int AS ldap_connections,
       (SELECT count(*) FROM tenant.scim_tokens s WHERE s.tenant_id = @tenant_id AND s.revoked_at IS NULL
          AND (s.expires_at IS NULL OR s.expires_at > NOW()))::int AS scim_tokens,
       (SELECT count(*) FROM tenant.directory_events e WHERE e.tenant_id = @tenant_id AND e.status = 'failed'
          AND e.resolution = 'open' AND e.started_at > NOW() - INTERVAL '24 hours')::int AS open_failures;

-- RecentIncidents returns the incidents still open and those resolved in the
-- last 14 days, newest first.
-- name: RecentIncidents :many
SELECT id, component, impact, title, detail, started_at, resolved_at
FROM platform.incidents
WHERE resolved_at IS NULL OR resolved_at > NOW() - INTERVAL '14 days'
ORDER BY started_at DESC
LIMIT 50;

-- name: OpenIncident :one
INSERT INTO platform.incidents (component, impact, title, detail)
VALUES (@component, @impact, @title, @detail)
RETURNING id;

-- name: ResolveIncident :execrows
UPDATE platform.incidents SET resolved_at = NOW() WHERE id = @id AND resolved_at IS NULL;
