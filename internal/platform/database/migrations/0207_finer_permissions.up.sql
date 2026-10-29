-- 0207_finer_permissions — finer administrative permissions, and built-in
-- Admin, Member and Viewer roles in every organisation.
--
-- user.write let its holder create and edit people but also delete, suspend
-- and purge them, set their passwords, reset their second factors and end
-- their sessions; tenant.write included deleting the organisation. Those now
-- have permissions of their own, and every role and machine credential
-- holding user.write or tenant.write today gets them, so no one's access
-- changes.
--
-- With custom roles only on paid plans, every administrator of a free
-- organisation had to be an owner. Each organisation now has built-in admin
-- (everything but deleting the organisation), member (no administration) and
-- viewer (read everything but secrets, whose read reveals them) roles,
-- read-only like owner and not counted against the plan's custom roles. An
-- organisation that already has a custom role of one of those names keeps it,
-- and gets no built-in role by it.
INSERT INTO rbac.permissions (key, description) VALUES
    ('user.delete', 'Delete, restore and purge people, and remove them from the organisation'),
    ('user.suspend', 'Suspend and reactivate people'),
    ('user.credentials', 'Set people''s passwords, reset their second factors and require them, remove their trusted and push devices'),
    ('session.revoke', 'End people''s sessions'),
    ('member.invite', 'Invite people, and resend or withdraw invitations'),
    ('tenant.delete', 'Delete the organisation, or call its deletion off')
ON CONFLICT (key) DO NOTHING;

-- The built-in roles below hold what their definitions say, not this.
INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT rp.role_id, np.id
FROM rbac.role_permissions rp
JOIN rbac.roles ro ON ro.id = rp.role_id
JOIN rbac.permissions op ON op.id = rp.permission_id
JOIN rbac.permissions np ON
     (op.key = 'user.write' AND np.key IN ('user.delete', 'user.suspend', 'user.credentials', 'session.revoke', 'member.invite'))
  OR (op.key = 'tenant.write' AND np.key = 'tenant.delete')
WHERE NOT (ro.is_system AND ro.name IN ('admin', 'member', 'viewer'))
ON CONFLICT DO NOTHING;

-- Machine credentials carry permissions as scopes: one holding user.write or
-- tenant.write today gets the new ones too.
UPDATE auth.api_keys SET scopes = scopes || ARRAY['user.delete', 'user.suspend', 'user.credentials', 'session.revoke', 'member.invite']
WHERE 'user.write' = ANY(scopes) AND NOT ('user.delete' = ANY(scopes));
UPDATE auth.service_principals SET scopes = scopes || ARRAY['user.delete', 'user.suspend', 'user.credentials', 'session.revoke', 'member.invite']
WHERE 'user.write' = ANY(scopes) AND NOT ('user.delete' = ANY(scopes));
UPDATE auth.agents SET scopes = scopes || ARRAY['user.delete', 'user.suspend', 'user.credentials', 'session.revoke', 'member.invite']
WHERE 'user.write' = ANY(scopes) AND NOT ('user.delete' = ANY(scopes));
UPDATE auth.api_keys SET scopes = scopes || ARRAY['tenant.delete']
WHERE 'tenant.write' = ANY(scopes) AND NOT ('tenant.delete' = ANY(scopes));
UPDATE auth.service_principals SET scopes = scopes || ARRAY['tenant.delete']
WHERE 'tenant.write' = ANY(scopes) AND NOT ('tenant.delete' = ANY(scopes));
UPDATE auth.agents SET scopes = scopes || ARRAY['tenant.delete']
WHERE 'tenant.write' = ANY(scopes) AND NOT ('tenant.delete' = ANY(scopes));

INSERT INTO rbac.roles (tenant_id, name, description, is_system)
SELECT t.id, r.name, r.description, TRUE
FROM tenant.tenants t
CROSS JOIN (VALUES
    ('admin', 'Administrator — everything but deleting the organisation'),
    ('member', 'Member — signs in to the organisation''s apps, no administration'),
    ('viewer', 'Viewer — reads everything, changes nothing')
) AS r (name, description)
WHERE NOT EXISTS (SELECT 1 FROM rbac.roles x WHERE x.tenant_id = t.id AND lower(x.name) = r.name);

INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT ro.id, p.id
FROM rbac.roles ro
JOIN rbac.permissions p ON
     (ro.name = 'admin' AND p.key <> 'tenant.delete')
  OR (ro.name = 'viewer' AND p.key LIKE '%.read' AND p.key <> 'secret.read')
WHERE ro.is_system AND ro.name IN ('admin', 'viewer')
ON CONFLICT DO NOTHING;
