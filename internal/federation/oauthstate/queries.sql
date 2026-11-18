-- Queries for the oauthstate domain: what a begun OAuth or OpenID Connect
-- sign-in keeps for its callback, under the hash of the state it sent. All
-- queries are STATIC.

-- name: InsertState :exec
INSERT INTO auth.oauth_states
    (state_hash, kind, organization_id, connection_id, provider, code_verifier, nonce_hash, redirect_uri,
     return_to, link_user_id, allow_create, expires_at)
VALUES (@state_hash, @kind, sqlc.narg('organization_id')::uuid, sqlc.narg('connection_id')::uuid,
        sqlc.narg('provider')::text, @code_verifier, sqlc.narg('nonce_hash')::text, @redirect_uri,
        sqlc.narg('return_to')::text, sqlc.narg('link_user_id')::uuid, @allow_create, @expires_at);

-- TakeState spends a state of kind as it reads it, so a callback carrying it
-- succeeds at most once. Given a connection, only that connection's state is
-- found, so another's callback can't spend it.
-- name: TakeState :one
DELETE FROM auth.oauth_states
WHERE state_hash = @state_hash AND kind = @kind
  AND (sqlc.narg('connection_id')::uuid IS NULL OR connection_id = sqlc.narg('connection_id')::uuid)
RETURNING organization_id, connection_id, provider, code_verifier, nonce_hash, redirect_uri, return_to,
          link_user_id, allow_create, expires_at;
