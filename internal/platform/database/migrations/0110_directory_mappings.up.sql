CREATE TABLE tenant.directory_mappings (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    source_attribute TEXT NOT NULL CHECK (char_length(source_attribute) BETWEEN 1 AND 128),
    target_field TEXT NOT NULL CHECK (target_field IN ('email','display_name','first_name','last_name','department','title','manager_id','groups')),
    value_type TEXT NOT NULL CHECK (value_type IN ('string','array')),
    transform TEXT NOT NULL CHECK (transform IN ('none','trim','lowercase','uppercase','extract')),
    pattern TEXT NOT NULL DEFAULT '' CHECK (char_length(pattern) <= 256),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX directory_mappings_connection ON tenant.directory_mappings(tenant_id,connection_id,created_at,id);
CREATE UNIQUE INDEX directory_mappings_active_target ON tenant.directory_mappings(tenant_id,connection_id,target_field) WHERE enabled;

CREATE TABLE tenant.directory_profiles (
    tenant_id UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(tenant_id,user_id,connection_id)
);
