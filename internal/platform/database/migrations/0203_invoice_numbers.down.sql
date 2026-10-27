-- 9002_invoice_numbers (down)
ALTER TABLE tenant.invoices DROP COLUMN IF EXISTS invoice_number;
DROP TABLE IF EXISTS platform.invoice_number_series;
