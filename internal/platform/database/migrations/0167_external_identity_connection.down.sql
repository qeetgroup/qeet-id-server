-- Keeps the most recently linked identity of each subject, which the old key
-- allows only one of.
DELETE FROM "user".external_identities ei
WHERE ei.id NOT IN (
    SELECT DISTINCT ON (tenant_id, provider, subject) id
    FROM "user".external_identities
    ORDER BY tenant_id, provider, subject, linked_at DESC, id
);

DROP INDEX "user".uq_ext_identity_provider;
CREATE UNIQUE INDEX uq_ext_identity_provider ON "user".external_identities (tenant_id, provider, subject);
ALTER TABLE "user".external_identities DROP COLUMN connection_id;
