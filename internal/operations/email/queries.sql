-- Queries for the email-templates domain.
-- Static queries against organization.email_templates live here and are compiled by
-- sqlc into ./dbgen. There are no dynamic queries in this domain.

-- name: ListEmailTemplateOverrides :many
SELECT template_key, subject, body, options
FROM organization.email_templates
WHERE organization_id = $1;

-- name: GetEmailTemplateOverride :one
SELECT subject, body, options
FROM organization.email_templates
WHERE organization_id = $1 AND template_key = $2;

-- name: UpsertEmailTemplate :exec
INSERT INTO organization.email_templates (organization_id, template_key, subject, body, options, updated_at)
VALUES (@organization_id, @template_key, @subject, @body, @options, NOW())
ON CONFLICT (organization_id, template_key) DO UPDATE
    SET subject    = EXCLUDED.subject,
        body       = EXCLUDED.body,
        options    = EXCLUDED.options,
        updated_at = NOW();

-- name: DeleteEmailTemplate :exec
DELETE FROM organization.email_templates
WHERE organization_id = @organization_id AND template_key = @template_key;

-- GetRecipientLocale is the language the account at an address chose for its
-- profile, empty for none, if the account belongs to the organization: its home
-- or one where it holds a role.
-- name: GetRecipientLocale :one
SELECT COALESCE(u.metadata->>'locale', '')::text AS locale
FROM account.users u
WHERE LOWER(u.email) = LOWER(@email) AND u.deleted_at IS NULL
  AND (u.organization_id = @organization_id::uuid
       OR EXISTS (SELECT 1 FROM rbac.user_roles r WHERE r.user_id = u.id AND r.organization_id = @organization_id::uuid));
