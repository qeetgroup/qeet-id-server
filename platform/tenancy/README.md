# platform/tenancy

Multi-tenancy primitives and context propagation.

Planned: `TenantID` type alias, `context.Context` helpers (`WithTenantID`, `TenantIDFromCtx`),
tenant resolution middleware (subdomain, path prefix, header), tenant existence cache.

Today tenancy is enforced via raw `tenant_id` columns in every domain. This package will
centralise the convention.
