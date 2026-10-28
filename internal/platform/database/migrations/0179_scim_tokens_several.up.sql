-- 0179_scim_tokens_several — an organisation can hold several SCIM tokens,
-- each named, with an optional expiry, and revoked one at a time.
--
-- An organisation had one token that never expired, and rotating it cut the
-- old one off at once, so provisioning broke until the identity provider had
-- the new one. A rotated token now names its replacement and keeps working
-- until its overlap ends, recorded as its expiry. A revoked token stays, for
-- the record, with revoked_at set. Each existing token carries on as its
-- organisation's first, named "SCIM token".
ALTER TABLE tenant.scim_tokens
    DROP CONSTRAINT scim_tokens_pkey,
    ADD COLUMN id          UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN name        TEXT NOT NULL DEFAULT 'SCIM token' CHECK (char_length(name) BETWEEN 1 AND 200),
    ADD COLUMN expires_at  TIMESTAMPTZ,
    ADD COLUMN revoked_at  TIMESTAMPTZ,
    ADD COLUMN replaced_by UUID;
