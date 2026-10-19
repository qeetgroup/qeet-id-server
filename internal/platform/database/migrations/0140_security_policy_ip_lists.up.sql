-- 0140_security_policy_ip_lists — drop the security policy's own IP lists.
--
-- ip_allowlist and ip_denylist were stored and shown but never consulted by any
-- sign-in, so they protected nobody. Address rules (tenant.ip_rules, with their
-- on/off switch) are the one address control, and every sign-in now asks them.
-- The entries are not moved into address rules: they never took effect, and
-- turning them on unannounced where an organisation already enforces address
-- rules could lock its people out.
ALTER TABLE tenant.security_policies DROP COLUMN IF EXISTS ip_allowlist;
ALTER TABLE tenant.security_policies DROP COLUMN IF EXISTS ip_denylist;
