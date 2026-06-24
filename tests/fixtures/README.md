# tests/fixtures/

Shared test helpers and fixtures used by Go integration and security tests.

## Contents

| File | Purpose |
|---|---|
| `db.go` | Testcontainer setup — starts a fresh Postgres instance for integration tests |
| `seed.go` | Insert minimal fixture data (tenant, users, roles) into a test DB |
| `http.go` | Helper to build an authenticated `*http.Request` for API testing |
| `tokens.go` | Mint test JWTs signed with a test-only EC key |

## Usage

```go
import "github.com/qeetgroup/qeet-id/tests/fixtures"

func TestSomething(t *testing.T) {
    pool := fixtures.NewTestDB(t)      // spins up testcontainer, runs migrations
    fixtures.SeedMinimal(t, pool)      // seeds 1 tenant, 3 users
    
    req := fixtures.AuthRequest(t, "GET", "/v1/users", fixtures.AdminToken(t))
    // ... use req with your handler
}
```

## Design notes

- `NewTestDB` uses `testcontainers-go` to spin up `postgres:16-alpine` — same version as `deploy/dev/docker-compose.yml`
- Each `TestXxx` gets its own database (via `CREATE DATABASE test_<uuid>`) to avoid cross-test contamination
- `SeedMinimal` inserts only what every test needs; tests add their own domain-specific data
- `AdminToken` mints a token with the `platform:admin` scope; `UserToken` mints a member-scoped token
- All tokens use a test-only P-256 key (`fixtures/testdata/signing-key.pem`); never use production keys in tests
