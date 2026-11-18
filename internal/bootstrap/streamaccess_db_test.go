//go:build integration

package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agent"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// unlimitedPlans is a plan without limits.
type unlimitedPlans struct{}

func (unlimitedPlans) Limit(context.Context, uuid.UUID, string) (int, error) { return -1, nil }

// TestStreamAccessFollowsWhatAdmittedTheReader checks the check an open
// activity stream keeps making: a reader with a live session and audit.read
// stays allowed, and is refused once the session ends, audit.read is gone, the
// token has expired, or they never belonged to the organization; an API key
// stays allowed as the route admits it until it is revoked.
func TestStreamAccessFollowsWhatAdmittedTheReader(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	reader, outsider := dbtest.User(t, organization, organization), dbtest.User(t, other, other)
	auditors := dbtest.Role(t, organization, "audit.read")
	dbtest.Assign(t, reader.ID, organization, auditors)
	session := func(userID, organizationID uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2) RETURNING id`, userID, organizationID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	policy := RoutePolicies()["GET /v1/activity/stream"]
	if policy.UserPermission != "audit.read" {
		t.Fatalf("the stream route's policy %+v; want it gated on audit.read", policy)
	}
	authSvc := authtest.New(t, pool)
	issuer := dbtest.Issuer(t)
	keys, err := apikey.NewService(pool, unlimitedPlans{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := httpx.NewAuthVerifier(httpx.AuthVerifier{
		Tokens: issuer, AgentStatus: agent.NewService(pool, issuer).AgentStatus, SessionUsed: authSvc.SessionUsed,
		SessionLive: authSvc.SessionLive, PrincipalLive: principal.NewService(pool, issuer).PrincipalLive, APIKeyLive: keys.Live,
	})
	if err != nil {
		t.Fatal(err)
	}
	access := streamAccess(verifier, rbac.NewRepository(pool), policy)
	asPerson := func(userID, organizationID, sessionID uuid.UUID, expires time.Time) *httpx.Principal {
		return &httpx.Principal{ActorType: "user", UserID: &userID, OrganizationID: &organizationID, SessionID: &sessionID, ExpiresAt: &expires}
	}
	allowed := func(what string, p *httpx.Principal, want bool) {
		t.Helper()
		if got, err := access(ctx, p); err != nil || got != want {
			t.Errorf("%s: allowed %v (%v), want %v", what, got, err, want)
		}
	}

	live := session(reader.ID, organization)
	soon := time.Now().Add(time.Hour)
	allowed("a reader with a live session and audit.read", asPerson(reader.ID, organization, live, soon), true)
	allowed("the same reader once the token has expired", asPerson(reader.ID, organization, live, time.Now().Add(-time.Second)), false)
	allowed("someone of another organization", asPerson(outsider.ID, organization, session(outsider.ID, other), soon), false)

	ended := session(reader.ID, organization)
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, ended); err != nil {
		t.Fatal(err)
	}
	allowed("a reader whose session was revoked", asPerson(reader.ID, organization, ended, soon), false)

	var keyID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash, scopes) VALUES ($1, $2, 'stream', $3, 'x', $4) RETURNING id`,
		organization, reader.ID, dbtest.Unique("k")[:8], policy.MachineScopes).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	key := &httpx.Principal{ActorType: "api_key", Subject: keyID.String(), OrganizationID: &organization, UserID: &reader.ID, Scopes: policy.MachineScopes}
	allowed("a live API key the route admits", key, policy.AllowAPIKey)
	if _, err := pool.Exec(ctx, `UPDATE auth.api_keys SET revoked_at = NOW() WHERE id = $1 AND organization_id = $2`, keyID, organization); err != nil {
		t.Fatal(err)
	}
	allowed("a revoked API key", key, false)

	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, reader.ID, organization); err != nil {
		t.Fatal(err)
	}
	allowed("a reader whose audit.read was taken away", asPerson(reader.ID, organization, live, soon), false)
}
