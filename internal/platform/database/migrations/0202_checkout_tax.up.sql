-- 0202_checkout_tax — a checkout records the tax it charges.
--
-- Tax is worked out before the payment opens and the provider charges the
-- total, so the invoice issued when the payment completes copies this
-- breakdown rather than working tax out again. amount_minor is the total
-- charged; the rows already here charged no tax.
ALTER TABLE tenant.billing_checkouts
    ADD COLUMN taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_rate_bps         INT    NOT NULL DEFAULT 0,
    ADD COLUMN tax_type             TEXT   NOT NULL DEFAULT 'none',
    ADD COLUMN place_of_supply      TEXT   NOT NULL DEFAULT '';

UPDATE tenant.billing_checkouts SET taxable_amount_minor = amount_minor;

ALTER TABLE tenant.signup_checkouts
    ADD COLUMN taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN tax_rate_bps         INT    NOT NULL DEFAULT 0,
    ADD COLUMN tax_type             TEXT   NOT NULL DEFAULT 'none',
    ADD COLUMN place_of_supply      TEXT   NOT NULL DEFAULT '';

UPDATE tenant.signup_checkouts SET taxable_amount_minor = amount_minor;
