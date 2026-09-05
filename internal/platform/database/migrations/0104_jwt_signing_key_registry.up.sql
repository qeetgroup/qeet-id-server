CREATE TABLE platform.jwt_signing_keys (
    kid                TEXT PRIMARY KEY,
    algorithm          TEXT        NOT NULL CHECK (algorithm = 'ES256'),
    state              TEXT        NOT NULL CHECK (state IN ('candidate', 'active', 'retired')),
    public_key_pem     TEXT        NOT NULL,
    private_key_ct     BYTEA,
    private_key_nonce  BYTEA,
    encryption_version SMALLINT    NOT NULL DEFAULT 1 CHECK (encryption_version = 1),
    activated_at       TIMESTAMPTZ,
    retire_at          TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT jwt_signing_private_storage_valid CHECK (
        (state IN ('candidate', 'active') AND private_key_ct IS NOT NULL AND private_key_nonce IS NOT NULL)
        OR
        (state = 'retired' AND private_key_ct IS NULL AND private_key_nonce IS NULL AND retire_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX jwt_signing_one_active
    ON platform.jwt_signing_keys ((state))
    WHERE state = 'active';

CREATE INDEX jwt_signing_retirement
    ON platform.jwt_signing_keys (retire_at)
    WHERE state = 'retired';
