-- 0080_abac_policies — tenant-scoped ABAC rules: effect (allow/deny) + resource/action matchers + a JSON condition tree evaluated at decision time.
-- '*' in resource_type/action matches any value, so one policy can cover a whole class.

create table auth.abac_policies (
    id              uuid        primary key default gen_random_uuid(),
    tenant_id       uuid        not null,
    name            text        not null,
    description     text        not null default '',
    effect          text        not null check (effect in ('allow','deny')),
    resource_type   text        not null,
    action          text        not null,
    condition       jsonb       not null default '{}',
    priority        int         not null default 0,
    enabled         boolean     not null default true,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (tenant_id, name)
);

-- Evaluate hot path: (tenant, resource_type, action) lookup. Wildcard rows are caught by an extra OR in the query, not this index, but it still scopes the scan to tenant + common cases.
create index idx_abac_policies_lookup
    on auth.abac_policies (tenant_id, resource_type, action);
