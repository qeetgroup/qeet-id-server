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

-- name: DeleteRelationTuple :one
-- Returns the tuple removed, for its audit entry.
DELETE FROM auth.relation_tuples WHERE id = @id AND tenant_id = @tenant_id
RETURNING object_type, object_id, relation, subject_type, subject_id, subject_relation;

-- name: ListRelationTuplesByObject :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, relation, subject_type, subject_id, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type AND object_id = @object_id
ORDER BY relation, subject_type, subject_id
LIMIT 1001;

-- name: FetchSubjects :many
-- Hot path for Check/Explain/Expand: fetch every subject granted relation on one object.
SELECT subject_type, subject_id, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type AND object_id = @object_id AND relation = @relation;

-- name: ListRelationTuplesBySubject :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, object_type, object_id, relation, subject_relation
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND subject_type = @subject_type AND subject_id = @subject_id
ORDER BY object_type, object_id, relation
LIMIT 1001;

-- ListRelationObjectTypes counts, for each type of object the tenant's tuples
-- name, its objects and tuples.
-- name: ListRelationObjectTypes :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT object_type, count(DISTINCT object_id)::int AS objects, count(*)::int AS tuples
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id
GROUP BY object_type
ORDER BY object_type
LIMIT 1001;

-- ListRelationObjects returns a page of the objects of one type the tenant's
-- tuples name, by id, after the cursor, with how many tuples each has.
-- name: ListRelationObjects :many
SELECT object_id, count(*)::int AS tuples
FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type AND object_id > @after
GROUP BY object_id
ORDER BY object_id
LIMIT @row_limit;

-- name: CountRelationObjects :one
SELECT count(DISTINCT object_id)::int FROM auth.relation_tuples
WHERE tenant_id = @tenant_id AND object_type = @object_type;

-- NamePeople names, by display name or else address, those of ids who belong
-- to the organisation: their home, or one they hold a role in.
-- name: NamePeople :many
SELECT u.id, COALESCE(NULLIF(u.display_name, ''), u.email)::text AS name
FROM account.users u
WHERE u.id = ANY(@ids::uuid[]) AND u.deleted_at IS NULL
  AND (u.tenant_id = @tenant_id OR EXISTS (
      SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = @tenant_id));
