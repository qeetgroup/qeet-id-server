-- 0208_invoices_tenant_id_id — a unique (tenant_id, id) on invoices, so a
-- checkout that pays one can refer to it by both and the database refuses one
-- pointing at another organisation's invoice.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS invoices_tenant_id_id_key
    ON tenant.invoices (tenant_id, id);
