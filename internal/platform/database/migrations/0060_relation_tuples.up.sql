-- 0060_relation_tuples — ReBAC (Zanzibar-style) tuples: subject is related to object via relation, e.g.
--   document:readme #viewer group:eng#member  (a "userset": everyone who is group:eng#member is a viewer).
-- Check resolves recursively (subject_relation != '' = a userset to expand). Complements RBAC/ABAC; per-tenant.
CREATE TABLE auth.relation_tuples (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    object_type      TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    relation         TEXT NOT NULL,
    subject_type     TEXT NOT NULL,            -- "user" (direct) or an object type (userset)
    subject_id       TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '', -- '' = direct subject; else the userset's relation
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_relation_tuple
    ON auth.relation_tuples (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation);
-- The hot path: fetch every tuple granting <relation> on an object.
CREATE INDEX idx_relation_tuple_object
    ON auth.relation_tuples (tenant_id, object_type, object_id, relation);
