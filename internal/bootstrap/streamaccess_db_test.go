//go:build integration

package bootstrap

import (
	"testing"
	"time"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestStreamAccessFollowsWhatAdmittedTheReader checks the check an open
// activity stream keeps making: a reader with a live session and audit.read
// stays allowed, and is refused once the session ends, audit.read is gone, the
// token has expired, or they never belonged to the organisation; an API key
// stays allowed as the route admits it until it is revoked.
func TestStreamAccessFollowsWhatAdmittedTheReader(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	reader, outsider := dbtest.User(t, tenant, tenant), dbtest.User(t, other, other)
	auditors := dbtest.Role(t, tenant, "audit.read")
	dbtest.Assign(t, reader.ID, tenant, auditors)
	session := func(userID, tenantID uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2) RETURNING id`, userID, tenantID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	policy := RoutePolicies()["GET /v1/activity/stream"]
	if policy.UserPermission != "audit.read" {
		t.Fatalf("the stream route's policy %+v; want it gated on audit.read", policy)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	keys := apikey.NewService(pool)
	access := streamAccess{verifier: &httpx.AuthVerifier{SessionLive: authSvc.SessionLive}, checker: rbac.NewRepository(pool), apiKeys: keys, policy: policy}
	asPerson := func(userID, tenantID, sessionID uuid.UUID, expires time.Time) *httpx.Principal {
		return &httpx.Principal{ActorType: "user", UserID: &userID, TenantID: &tenantID, SessionID: &sessionID, ExpiresAt: &expires}
	}
	allowed := func(what string, p *httpx.Principal, want bool) {
		t.Helper()
		if got, err := access.Allowed(ctx, p); err != nil || got != want {
			t.Errorf("%s: allowed %v (%v), want %v", what, got, err, want)
		}
	}

	live := session(reader.ID, tenant)
	soon := time.Now().Add(time.Hour)
	allowed("a reader with a live session and audit.read", asPerson(reader.ID, tenant, live, soon), true)
	allowed("the same reader once the token has expired", asPerson(reader.ID, tenant, live, time.Now().Add(-time.Second)), false)
	allowed("someone of another organisation", asPerson(outsider.ID, tenant, session(outsider.ID, other), soon), false)

	ended := session(reader.ID, tenant)
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, ended); err != nil {
		t.Fatal(err)
	}
	allowed("a reader whose session was revoked", asPerson(reader.ID, tenant, ended, soon), false)

	var keyID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash, scopes) VALUES ($1, $2, 'stream', $3, 'x', $4) RETURNING id`,
		tenant, reader.ID, dbtest.Unique("k")[:8], policy.MachineScopes).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	key := &httpx.Principal{ActorType: "api_key", Subject: keyID.String(), TenantID: &tenant, UserID: &reader.ID, Scopes: policy.MachineScopes}
	allowed("a live API key the route admits", key, policy.AllowAPIKey)
	if _, err := pool.Exec(ctx, `UPDATE auth.api_keys SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2`, keyID, tenant); err != nil {
		t.Fatal(err)
	}
	allowed("a revoked API key", key, false)

	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, reader.ID, tenant); err != nil {
		t.Fatal(err)
	}
	allowed("a reader whose audit.read was taken away", asPerson(reader.ID, tenant, live, soon), false)
}
