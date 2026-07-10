-- Reverse-lookup index: find all objects a given subject appears in.
-- Without this, "what can user X access?" is a full tenant-table scan.
-- Used by the new /relation-tuples?subject= and /relation-tuples/graph endpoints.
CREATE INDEX idx_relation_tuple_subject
    ON auth.relation_tuples (tenant_id, subject_type, subject_id);
