# qeetid-go

Server-side Go SDK for [Qeet ID](https://qeetid.com) — manage users and tenants,
run authorization checks, and verify sessions/JWTs. **No third-party
dependencies** (standard library only).

```bash
go get github.com/qeetgroup/qeetid-go
```

> Authenticate with a secret API key (`qk_…`). Never embed it in client code.

## Usage

Import the package as `qeetidsdk` so you can name the client value `qeetid`
(otherwise the variable would shadow the package):

```go
import (
	"context"
	"os"

	qeetidsdk "github.com/qeetgroup/qeetid-go"
)

qeetid := qeetidsdk.New(qeetidsdk.Options{APIKey: os.Getenv("QEETID_API_KEY")})
ctx := context.Background()

// Verify the caller's token locally against the published JWKS (cached).
claims, err := qeetid.Sessions.Verify(ctx, accessToken)

// Authorization
ok, err := qeetid.Can(ctx, qeetidsdk.PermissionCheck{
	User:       claims.UserID,
	Tenant:     claims.TenantID,
	Permission: "billing:write",
})

// Manage users
user, err := qeetid.Users.Create(ctx, qeetidsdk.CreateUserInput{Email: "new@acme.com"})
page, err := qeetid.Users.List(ctx, qeetidsdk.ListParams{Tenant: "acme", Limit: 50})
```

## API

| Call | Description |
| --- | --- |
| `qeetid.Sessions.Verify(ctx, token, opts…)` | Verify an ES256 token against JWKS; returns `*Claims`. |
| `qeetid.Can(ctx, PermissionCheck{…})` | Single RBAC check → `bool`. |
| `qeetid.CanAll(ctx, user, tenant, perms)` | True only if all pass. |
| `qeetid.Users.{Create,Get,Update,Delete,SetPassword,List}` | User management. |
| `qeetid.Tenants.{Create,Get,Update,Delete,List}` | Tenant management. |

## Errors

Every failed call returns a `*qeetid.Error` with `Status`, `Code`, `Message`,
and `RequestID`:

```go
user, err := qeetid.Users.Get(ctx, "usr_missing")
var apiErr *qeetidsdk.Error
if errors.As(err, &apiErr) {
	switch {
	case apiErr.IsNotFound():     // 404
	case apiErr.IsRateLimited():  // 429 — see apiErr.RetryAfterSeconds
	case apiErr.IsUnauthorized(): // 401 — bad API key
	}
}
```

429 and 5xx (on idempotent calls) are retried automatically with backoff,
honoring `Retry-After`.

## Configuration

```go
qeetidsdk.New(qeetidsdk.Options{
	APIKey:     "qk_…",                  // required
	BaseURL:    "https://api.qeetid.com", // default
	HTTPClient: &http.Client{Timeout: 10 * time.Second},
	MaxRetries: 2,
})
```
