-- Queries for the rebac domain.
-- All five SQL statements are fully static (the Zanzibar-style recursion
-- lives in Go, not SQL), so all are converted.

-- name: InsertRelationTuple :one
INSERT INTO auth.relation_tuples
    (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
VALUES (@tenant_id, @object_type, @object_id, @relation, @subject_type, @subject_id, @subject_relation)
ON CONFLICT (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id
RETURNING id;

-- name: DeleteRelationTuple :execrows
DELETE FROM auth.relation_tuples WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListRelationTuplesByObject :many
SELECT id, relation, subject_type, subject_id, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type AND object_id = @object_id
ORDER BY relation, subject_type, subject_id;

-- name: FetchSubjects :many
-- Hot path for Check/Explain/Expand: fetch every subject granted relation on one object.
SELECT subject_type, subject_id, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type AND object_id = @object_id AND relation = @relation;

-- name: ListRelationTuplesBySubject :many
SELECT id, object_type, object_id, relation, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND subject_type = @subject_type AND subject_id = @subject_id
ORDER BY object_type, object_id, relation;
