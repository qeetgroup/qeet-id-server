-- 0062_credentials — issuer-side registry of W3C Verifiable Credentials (ES256 JWT-VC, verifiable via our JWKS); the signed VC is held by the subject, claims kept here for list/revoke/re-issue/audit
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
