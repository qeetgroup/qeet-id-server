-- 0203_invoice_numbers — a GST invoice number on every invoice that charges
-- something.
--
-- One series per Indian financial year (April to March), such as
-- 2026-27/000001. The series row is taken in the transaction that issues the
-- invoice, so the numbers run on without gaps; zero invoices have none. The
-- next migration makes the numbers unique.
CREATE TABLE platform.invoice_number_series (
    financial_year TEXT PRIMARY KEY, -- such as 2026-27
    last_number    BIGINT NOT NULL
);

ALTER TABLE tenant.invoices ADD COLUMN invoice_number TEXT;
