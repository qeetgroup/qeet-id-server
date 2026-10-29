-- 9001_checkout_tax (down)
ALTER TABLE tenant.signup_checkouts
    DROP COLUMN IF EXISTS taxable_amount_minor,
    DROP COLUMN IF EXISTS tax_amount_minor,
    DROP COLUMN IF EXISTS tax_rate_bps,
    DROP COLUMN IF EXISTS tax_type,
    DROP COLUMN IF EXISTS place_of_supply;

ALTER TABLE tenant.billing_checkouts
    DROP COLUMN IF EXISTS taxable_amount_minor,
    DROP COLUMN IF EXISTS tax_amount_minor,
    DROP COLUMN IF EXISTS tax_rate_bps,
    DROP COLUMN IF EXISTS tax_type,
    DROP COLUMN IF EXISTS place_of_supply;
