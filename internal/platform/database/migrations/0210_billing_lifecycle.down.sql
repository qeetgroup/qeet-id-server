ALTER TABLE tenant.signup_checkouts DROP COLUMN IF EXISTS payment_method;
ALTER TABLE tenant.billing_checkouts
    DROP CONSTRAINT IF EXISTS billing_checkouts_invoice_fkey,
    DROP COLUMN IF EXISTS payment_method,
    DROP COLUMN IF EXISTS invoice_id;
ALTER TABLE tenant.invoices
    DROP COLUMN IF EXISTS emailed_at,
    DROP COLUMN IF EXISTS sac,
    DROP COLUMN IF EXISTS supplier_gstin,
    DROP COLUMN IF EXISTS billed_to,
    DROP COLUMN IF EXISTS payment_reference,
    DROP COLUMN IF EXISTS paid_at,
    DROP COLUMN IF EXISTS due_at,
    DROP COLUMN IF EXISTS kind;
ALTER TABLE tenant.subscriptions DROP COLUMN IF EXISTS ended_at;
