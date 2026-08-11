-- 0094_invoice_tax (down)
ALTER TABLE tenant.invoices
    DROP COLUMN IF EXISTS taxable_amount_minor,
    DROP COLUMN IF EXISTS tax_amount_minor,
    DROP COLUMN IF EXISTS tax_rate_bps,
    DROP COLUMN IF EXISTS tax_type,
    DROP COLUMN IF EXISTS place_of_supply;
