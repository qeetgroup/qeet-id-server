-- Queries for the email-templates domain.
-- Static queries against tenant.email_templates live here and are compiled by
-- sqlc into ./dbgen. There are no dynamic queries in this domain.

-- name: ListEmailTemplateOverrides :many
SELECT template_key, subject, body, options
FROM tenant.email_templates
WHERE tenant_id = $1;

-- name: GetEmailTemplateOverride :one
SELECT subject, body, options
FROM tenant.email_templates
WHERE tenant_id = $1 AND template_key = $2;

-- name: UpsertEmailTemplate :exec
INSERT INTO tenant.email_templates (tenant_id, template_key, subject, body, options, updated_at)
VALUES (@tenant_id, @template_key, @subject, @body, @options, NOW())
ON CONFLICT (tenant_id, template_key) DO UPDATE
    SET subject    = EXCLUDED.subject,
        body       = EXCLUDED.body,
        options    = EXCLUDED.options,
        updated_at = NOW();

-- name: DeleteEmailTemplate :exec
DELETE FROM tenant.email_templates
WHERE tenant_id = @tenant_id AND template_key = @template_key;
