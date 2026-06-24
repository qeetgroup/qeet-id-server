# Adding a New Domain

This guide walks through adding a new subdomain to the Qeet ID monolith, following the established patterns.

## When to add a new domain

Add a new domain when you need to introduce a new bounded concept with its own:
- Persistent data (needs a migration)
- Business logic (service layer)
- API surface (HTTP handler)

If you're extending an existing domain (e.g., adding a field to users), modify the existing domain rather than creating a new one.

## Step 1: Create the domain package

Choose the right bounded context from:
- `domains/identity/` — user management, organizations
- `domains/access/` — authentication, authorization, security
- `domains/federation/` — protocol bridges (OIDC, SAML, SCIM)
- `domains/developer/` — API access, automation, webhooks
- `domains/operations/` — audit, billing, compliance, analytics

Create the triplet:

```
domains/<context>/<name>/
  ├── <name>.go       ← types, interfaces, Service struct
  ├── repository.go   ← persistence
  └── http.go         ← HTTP handler + Mount()
```

**`<name>.go` template:**
```go
package <name>

import (
    "context"
    "github.com/qeetgroup/qeet-id/platform/errs"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Widget is a [brief description].
type Widget struct {
    ID       string
    TenantID string
    Name     string
}

type CreateInput struct {
    Name string
}

// auditLogger is a consumer-declared interface — we declare what we need,
// not what audit.Service provides. Wired in buildDeps().
type auditLogger interface {
    Record(ctx context.Context, e audit.Event) error
}

type Service struct {
    db    *pgxpool.Pool
    audit auditLogger
}

func New(db *pgxpool.Pool, audit auditLogger) *Service {
    return &Service{db: db, audit: audit}
}

func (s *Service) Create(ctx context.Context, tenantID string, in CreateInput) (*Widget, error) {
    // validate
    if in.Name == "" {
        return nil, errs.ErrBadRequest.WithDetail("name is required")
    }
    // persist + audit
    // ...
}
```

## Step 2: Write the migration

```bash
# Create migration files
touch migrations/0063_widgets.up.sql
touch migrations/0063_widgets.down.sql
```

**`0063_widgets.up.sql`:**
```sql
CREATE TABLE platform.widgets (
    id         TEXT      NOT NULL PRIMARY KEY,
    tenant_id  TEXT      NOT NULL,
    name       TEXT      NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON platform.widgets (tenant_id);
```

**`0063_widgets.down.sql`:**
```sql
DROP TABLE IF EXISTS platform.widgets;
```

Apply locally:
```bash
make migrate-up
```

## Step 3: Declare cross-domain interfaces in the consumer

If your domain needs to call another domain (e.g., audit logging), declare a minimal interface in **your** package — not in the other package:

```go
// In your domain package:
type auditLogger interface {
    Record(ctx context.Context, e audit.Event) error
}
```

This keeps your domain's compilation independent of the audit domain's full interface.

## Step 4: Wire in `cmd/server/main.go`

`buildDeps()` in `cmd/server/main.go` is the composition root. Add your service:

```go
func buildDeps(cfg *config.Config, pool *pgxpool.Pool, ...) Deps {
    // Existing deps...
    widgetSvc := widget.New(pool, auditSvc)

    return Deps{
        // Existing...
        Widgets: widgetSvc,
    }
}
```

Also add the handler to the `Deps` struct (usually in `platform/http/router.go` or a local `deps.go`).

## Step 5: Mount the handler in the router

In `platform/http/router.go`:

```go
r.Route("/v1", func(r chi.Router) {
    // existing mounts...
    deps.Widgets.Mount(r)
})
```

**`http.go` Mount example:**
```go
func (h *Handler) Mount(r chi.Router) {
    r.Get("/widgets", h.list)
    r.Post("/widgets", h.create)
    r.Get("/widgets/{id}", h.get)
    r.Delete("/widgets/{id}", h.delete)
}
```

## Step 6: Add routes to `api/openapi/`

**This is mandatory.** CI (`platform/http/openapi_coverage_test.go`) will fail if any mounted route is missing from the spec.

Add path entries to `api/openapi/`:

```yaml
paths:
  /v1/widgets:
    get:
      operationId: listWidgets
      tags: [Widgets]
      security:
        - bearerAuth: []
      # ...
    post:
      operationId: createWidget
      # ...
```

Run the coverage test to verify:
```bash
go test ./platform/http/... -run TestOpenAPICoverage
```

## Step 7: Write an integration test

Add a test file in `tests/integration/`:

```go
// tests/integration/widget_test.go
//go:build integration

package integration

func TestWidget_CreateAndList(t *testing.T) {
    // Uses testcontainers — real Postgres, real migrations
    // ...
}
```

Run:
```bash
make test-integration
```

## Checklist

- [ ] Domain package created with `<name>.go`, `repository.go`, `http.go`
- [ ] Migration pair written and applied (`make migrate-up`)
- [ ] Cross-domain interfaces declared in the consumer package
- [ ] Service wired in `cmd/server/main.go:buildDeps()`
- [ ] Handler mounted in `platform/http/router.go`
- [ ] Routes added to `api/openapi/`
- [ ] OpenAPI coverage test passes
- [ ] Integration test written
- [ ] Architecture tests pass (`make test`)
