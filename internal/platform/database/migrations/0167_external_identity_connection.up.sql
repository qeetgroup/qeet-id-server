-- 0167_external_identity_connection — an SSO identity belongs to its connection.
--
-- A SAML or LDAP identity was keyed by organisation and subject alone, so any
-- connection of the organisation could assert another connection's subject and
-- sign in as the person it was linked to. It now names the connection that
-- asserted it. Identities in an organisation with one connection of their kind
-- move to it; the rest link again at their next sign-in. Social identities name
-- no connection.
ALTER TABLE "user".external_identities ADD COLUMN connection_id UUID;

UPDATE "user".external_identities ei SET connection_id = c.id
FROM (SELECT tenant_id, min(id::text)::uuid AS id FROM tenant.saml_connections
      GROUP BY tenant_id HAVING count(*) = 1) c
WHERE ei.provider = 'saml' AND ei.tenant_id = c.tenant_id;

UPDATE "user".external_identities ei SET connection_id = c.id
FROM (SELECT tenant_id, min(id::text)::uuid AS id FROM tenant.ldap_connections
      GROUP BY tenant_id HAVING count(*) = 1) c
WHERE ei.provider = 'ldap' AND ei.tenant_id = c.tenant_id;

DROP INDEX "user".uq_ext_identity_provider;
CREATE UNIQUE INDEX uq_ext_identity_provider
    ON "user".external_identities (tenant_id, provider, connection_id, subject) NULLS NOT DISTINCT;
