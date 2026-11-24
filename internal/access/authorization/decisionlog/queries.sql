-- Queries for the decision-log domain, compiled by sqlc into ./dbgen.

-- ListDecisions returns a page of the organization's decisions, newest first,
-- before the cursor (before_ts, before_id) when it is set, of the subject,
-- source and answer when given.
-- name: ListDecisions :many
SELECT id, decided_at, source, caller_type, caller_id, caller_client, subject, resource, action,
       allowed, model, rule, reason_code
FROM auth.authz_decisions
WHERE organization_id = @organization_id
  AND (sqlc.narg('subject')::text IS NULL OR subject = sqlc.narg('subject'))
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
  AND (sqlc.narg('allowed')::boolean IS NULL OR allowed = sqlc.narg('allowed'))
  AND decided_at >= @since
  AND (sqlc.narg('before_ts')::timestamptz IS NULL
       OR (decided_at, id) < (sqlc.narg('before_ts')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY decided_at DESC, id DESC
LIMIT @row_limit;

-- name: InsertDecisions :exec
-- Writes a batch of decisions given column by column, the i-th decision from
-- the i-th element of each array; an empty caller ID is none. COPY isn't
-- allowed on a table with row-level security, so it is an INSERT.
INSERT INTO auth.authz_decisions
    (organization_id, decided_at, source, caller_type, caller_id, caller_client, subject, resource, action, allowed, model, rule, reason_code)
SELECT (@organization_ids::uuid[])[i], (@decided_at::timestamptz[])[i], (@sources::text[])[i], (@caller_types::text[])[i],
       NULLIF((@caller_ids::text[])[i], '')::uuid, (@caller_clients::text[])[i], (@subjects::text[])[i],
       (@resources::text[])[i], (@actions::text[])[i], (@allowed::boolean[])[i], (@models::text[])[i],
       (@rules::text[])[i], (@reason_codes::text[])[i]
FROM generate_subscripts(@organization_ids::uuid[], 1) AS i;
