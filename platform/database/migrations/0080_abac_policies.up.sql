-- ABAC (attribute-based access control) policy store. Each policy is a
-- tenant-scoped rule: effect (allow/deny) + resource/action matchers +
-- a JSON condition tree evaluated at decision time.
--
-- Wildcard values ('*') in resource_type or action match any value so a
-- single policy can cover an entire resource class or action class without
-- enumerating every combination.

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

-- Point lookup for the evaluate hot path: given a tenant, find all enabled
-- policies matching a resource_type and action (the '*' wildcard rows are
-- caught by an additional OR in the query rather than by this index alone,
-- but the index still reduces the scan by scoping to tenant + common cases).
create index idx_abac_policies_lookup
    on auth.abac_policies (tenant_id, resource_type, action);
