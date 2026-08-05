-- 0091_billing_profile — per-tenant billing & tax details for invoicing.
-- Captures the legal entity, billing address, and a tax ID (GSTIN for India,
-- VAT for the EU) that B2B invoices must carry. One row per tenant, created
-- lazily on first save. Tax *calculation* is intentionally out of scope here —
-- this only stores the details; a later change wires them into invoice totals.
CREATE TABLE tenant.billing_profiles (
    tenant_id      UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    legal_name     TEXT NOT NULL DEFAULT '',
    billing_email  TEXT NOT NULL DEFAULT '',
    address_line1  TEXT NOT NULL DEFAULT '',
    address_line2  TEXT NOT NULL DEFAULT '',
    city           TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT '',
    postal_code    TEXT NOT NULL DEFAULT '',
    country        TEXT NOT NULL DEFAULT '',
    tax_id_type    TEXT NOT NULL DEFAULT 'none'
        CHECK (tax_id_type IN ('none', 'gstin', 'vat')),
    tax_id         TEXT NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
