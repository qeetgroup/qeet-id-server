-- Queries for the decision-log domain. Batches are written by insertDecisions
-- (decisionlog.go): sqlc cannot type an unnest of many arrays.

-- ListDecisions returns a page of the organization's decisions, newest first,
-- before the cursor, of the subject, source and answer when given.
-- name: ListDecisions :many
SELECT id, decided_at, source, caller_type, caller_id, caller_client, subject, resource, action,
       allowed, model, rule, reason_code
FROM auth.authz_decisions
WHERE organization_id = @organization_id
  AND (sqlc.narg('subject')::text IS NULL OR subject = sqlc.narg('subject'))
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
  AND (sqlc.narg('allowed')::boolean IS NULL OR allowed = sqlc.narg('allowed'))
  AND decided_at >= @since
  AND (decided_at, id) < (@before_ts::timestamptz, @before_id::uuid)
ORDER BY decided_at DESC, id DESC
LIMIT @row_limit;
