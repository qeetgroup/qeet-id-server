-- Queries for account notices, compiled by sqlc into ./dbgen.

-- name: NoticeAddress :one
-- The address a notice to the account goes to, and its home organization.
SELECT email, organization_id FROM account.users WHERE id = @user_id AND deleted_at IS NULL;
