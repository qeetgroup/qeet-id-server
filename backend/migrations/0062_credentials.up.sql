-- Verifiable Credentials (W3C VC, JWT serialization). Qeet ID issues ES256-
-- signed credentials (verifiable via the same JWKS) and tracks them here so
-- they can be listed and revoked. The signed JWT-VC is held by the subject;
-- this table is the issuer-side registry (claims kept for re-issue/audit).
CREATE TABLE auth.credentials (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,            -- credentialSubject id (e.g. user uuid, DID, email)
    type        TEXT NOT NULL,            -- VC type, e.g. "EmploymentCredential"
    claims      JSONB NOT NULL DEFAULT '{}',
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_credentials_tenant ON auth.credentials (tenant_id, issued_at DESC);
