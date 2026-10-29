DELETE FROM rbac.roles WHERE is_system AND name IN ('admin', 'member', 'viewer');
DELETE FROM rbac.permissions WHERE key IN ('user.delete', 'user.suspend', 'user.credentials', 'session.revoke', 'member.invite', 'tenant.delete');
