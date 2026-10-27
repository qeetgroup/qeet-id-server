-- 9003_invoice_number_unique (down)
DROP INDEX CONCURRENTLY IF EXISTS tenant.uq_invoices_invoice_number;
