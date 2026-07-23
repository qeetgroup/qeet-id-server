-- 0078_rebac_graph_index — reverse index (subject → objects) so "what can user X access?" isn't a full tenant scan; backs /relation-tuples?subject= and /graph
CREATE INDEX idx_relation_tuple_subject
    ON auth.relation_tuples (tenant_id, subject_type, subject_id);
