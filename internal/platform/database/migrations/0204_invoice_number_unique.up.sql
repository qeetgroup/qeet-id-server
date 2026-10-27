-- 0204_invoice_number_unique — an invoice number is issued once.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_invoices_invoice_number
    ON tenant.invoices (invoice_number);
