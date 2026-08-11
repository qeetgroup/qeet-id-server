-- 0094_invoice_tax — record the tax breakdown on invoices.
-- amount_minor becomes the TOTAL charged (taxable + tax); taxable_amount_minor is
-- the net. Existing rows carried no tax, so backfill taxable = amount_minor.
ALTER TABLE tenant.invoices
    ADD COLUMN taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_rate_bps         INT    NOT NULL DEFAULT 0,
    ADD COLUMN tax_type             TEXT   NOT NULL DEFAULT 'none',
    ADD COLUMN place_of_supply      TEXT   NOT NULL DEFAULT '';

UPDATE tenant.invoices SET taxable_amount_minor = amount_minor WHERE taxable_amount_minor = 0;
