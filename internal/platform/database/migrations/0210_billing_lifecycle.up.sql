-- 0210_billing_lifecycle — a subscription ends or renews when its period ends;
-- an invoice falls due, is settled, keeps who it was billed to and the
-- supplier's GSTIN and SAC, and is emailed; a checkout keeps what it was paid
-- with, and can pay an open invoice rather than buy a plan.

ALTER TABLE tenant.subscriptions ADD COLUMN ended_at TIMESTAMPTZ;

-- kind is 'purchase' for a plan bought or changed and 'renewal' for the next
-- period the renewal job bills. billed_to is the billing profile as it stood
-- when the invoice was issued.
ALTER TABLE tenant.invoices
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'purchase' CHECK (kind IN ('purchase', 'renewal')),
    ADD COLUMN due_at TIMESTAMPTZ,
    ADD COLUMN paid_at TIMESTAMPTZ,
    ADD COLUMN payment_reference TEXT NOT NULL DEFAULT '',
    ADD COLUMN billed_to JSONB,
    ADD COLUMN supplier_gstin TEXT NOT NULL DEFAULT '',
    ADD COLUMN sac TEXT NOT NULL DEFAULT '',
    ADD COLUMN emailed_at TIMESTAMPTZ;

UPDATE tenant.invoices SET paid_at = issued_at WHERE status = 'paid';

-- invoice_id is the open invoice a checkout pays; payment_method is what the
-- provider reported it was paid with.
ALTER TABLE tenant.billing_checkouts
    ADD COLUMN invoice_id UUID,
    ADD COLUMN payment_method JSONB,
    ADD CONSTRAINT billing_checkouts_invoice_fkey FOREIGN KEY (tenant_id, invoice_id)
        REFERENCES tenant.invoices (tenant_id, id);

ALTER TABLE tenant.signup_checkouts ADD COLUMN payment_method JSONB;
