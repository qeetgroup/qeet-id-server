-- Queries for the sales-leads domain (in-app "Contact sales").

-- name: InsertSalesLead :one
INSERT INTO platform.sales_leads
    (tenant_id, user_id, name, email, company, team_size, message, source)
VALUES (sqlc.narg('tenant_id'), sqlc.narg('user_id'), @name, @email, @company,
        @team_size, @message, @source)
RETURNING id;
