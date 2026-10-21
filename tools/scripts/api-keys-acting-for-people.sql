-- api-keys-acting-for-people.sql — lists live API keys that act for a person. Read-only.
--
-- A key presents itself as its user on every call. Keys used to accept any user
-- id when they were created, and nobody recorded who created them, so review
-- every row: revoke a key that acts for someone other than the person who
-- created it, and any key whose person is not a member of its organization
-- (member_of_org = false), and tell that person. created_by is filled in only for
-- keys created since key creation is audited (apikey.created).
--
--   psql "$DATABASE_URL" -f tools/scripts/api-keys-acting-for-people.sql
SELECT k.tenant_id,
       k.id AS key_id,
       k.name,
       k.prefix,
       k.user_id,
       u.email AS acts_for,
       COALESCE(u.tenant_id = k.tenant_id, FALSE)
         OR EXISTS (
             SELECT 1 FROM rbac.user_roles m
             JOIN rbac.roles r ON r.id = m.role_id AND r.tenant_id = m.tenant_id
             WHERE m.user_id = k.user_id AND m.tenant_id = k.tenant_id
         ) AS member_of_org,
       creator.actor_user_id AS created_by,
       k.created_at,
       k.last_used_at
FROM auth.api_keys k
LEFT JOIN "user".users u ON u.id = k.user_id
LEFT JOIN LATERAL (
    SELECT e.actor_user_id FROM audit.events e
    WHERE e.action = 'apikey.created' AND e.resource_id = k.id
    ORDER BY e.created_at
    LIMIT 1
) creator ON TRUE
WHERE k.user_id IS NOT NULL
  AND k.revoked_at IS NULL
  AND (k.expires_at IS NULL OR k.expires_at > NOW())
ORDER BY k.tenant_id, k.created_at;
