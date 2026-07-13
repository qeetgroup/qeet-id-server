-- Compliance evidence runs. Each row is an immutable snapshot of one
-- on-demand compliance check pass for a tenant+framework pair.
-- Controls (per-control check results) are stored as JSONB so the full
-- report is retrievable without a JOIN, and the schema can evolve without
-- a migration for each new control.

create table tenant.compliance_evidence_runs (
    id              uuid        primary key default gen_random_uuid(),
    tenant_id       uuid        not null,
    framework       text        not null check (framework in ('soc2','iso27001')),
    generated_at    timestamptz not null default now(),
    generated_by    uuid,                     -- actor user id; null = system/API-key
    pass_count      int         not null default 0,
    fail_count      int         not null default 0,
    na_count        int         not null default 0,
    controls        jsonb       not null default '[]'
);

-- Tenant+framework list ordered by recency (list-runs query).
create index idx_compliance_evidence_runs_lookup
    on tenant.compliance_evidence_runs (tenant_id, framework, generated_at desc);
