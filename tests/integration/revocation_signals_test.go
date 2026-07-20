//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/domains/access/authentication"
	"github.com/qeetgroup/qeet-id-server/domains/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/domains/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/domains/operations/audit"
)

// subscribeTo creates a webhook subscription scoped to exactly the given
// event types, so Enqueue's ANY(events) filter only matches what this test
// cares about.
func subscribeTo(t *testing.T, ctx context.Context, wh *webhook.Service, tenantID uuid.UUID, events []string) {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := wh.Create(ctx, tx, webhook.CreateInput{
		TenantID: tenantID, URL: "https://example.test/hook", Events: events,
	}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

type queuedDelivery struct {
	EventType string
	Payload   map[string]any
}

func queuedDeliveries(t *testing.T, ctx context.Context, tenantID uuid.UUID, eventType string) []queuedDelivery {
	t.Helper()
	rows, err := testPool.Query(ctx, `
		SELECT d.event_type, d.payload
		FROM tenant.webhook_deliveries d
		JOIN tenant.webhook_subscriptions sub ON sub.id = d.subscription_id
		WHERE sub.tenant_id = $1 AND d.event_type = $2
		ORDER BY d.created_at, d.id
	`, tenantID, eventType)
	if err != nil {
		t.Fatalf("query deliveries: %v", err)
	}
	defer rows.Close()
	var out []queuedDelivery
	for rows.Next() {
		var d queuedDelivery
		var raw []byte
		if err := rows.Scan(&d.EventType, &raw); err != nil {
			t.Fatalf("scan delivery: %v", err)
		}
		if err := json.Unmarshal(raw, &d.Payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		out = append(out, d)
	}
	return out
}

// tenantScopedSession signs a fresh tenant-less user in, makes them a member
// of tenantID, and switches into it — the shortest path to a real,
// tenant-scoped session + refresh token for these tests.
func tenantScopedSession(t *testing.T, ctx context.Context, svc *auth.Service, tenantID uuid.UUID) (*auth.TokenPair, uuid.UUID) {
	t.Helper()
	email := uniqueSlug("revoc") + "@example.com"
	_, u, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	addTenantMember(t, ctx, tenantID, u.ID)
	pair, err := svc.SwitchTenant(ctx, u.ID, tenantID, "203.0.113.9", "test-agent")
	if err != nil {
		t.Fatalf("switch tenant: %v", err)
	}
	return pair, u.ID
}

// TestLogout_EmitsSessionRevokedWebhook proves the whole chain end to end: a
// tenant that subscribed to "session.revoked" gets a queued delivery the
// moment a session is logged out — not just an audit row, and not waiting
// out the access-token TTL.
func TestLogout_EmitsSessionRevokedWebhook(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("revoc"))

	authSvc, _ := newAuth()
	wh := webhook.NewService(testPool)
	authSvc.SetEmitter(wh.Enqueue)
	subscribeTo(t, ctx, wh, tenantID, []string{"session.revoked"})

	pair, userID := tenantScopedSession(t, ctx, authSvc, tenantID)

	if err := authSvc.Logout(ctx, pair.SessionID); err != nil {
		t.Fatalf("logout: %v", err)
	}

	deliveries := queuedDeliveries(t, ctx, tenantID, "session.revoked")
	if len(deliveries) != 1 {
		t.Fatalf("queued session.revoked deliveries = %d, want 1", len(deliveries))
	}
	d := deliveries[0]
	if d.Payload["reason"] != "logout" {
		t.Errorf("payload.reason = %v, want logout", d.Payload["reason"])
	}
	if d.Payload["user_id"] != userID.String() {
		t.Errorf("payload.user_id = %v, want %v", d.Payload["user_id"], userID)
	}

	// Logging out an already-revoked session is a no-op — no second delivery.
	if err := authSvc.Logout(ctx, pair.SessionID); err != nil {
		t.Fatalf("second logout: %v", err)
	}
	if got := queuedDeliveries(t, ctx, tenantID, "session.revoked"); len(got) != 1 {
		t.Fatalf("deliveries after repeat logout = %d, want still 1", len(got))
	}
}

// TestRefreshReuse_EmitsSessionRevokedWebhook covers the theft-detection
// path: reusing an already-rotated refresh token revokes the session and
// must queue the same signal as an explicit logout.
func TestRefreshReuse_EmitsSessionRevokedWebhook(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("revoc-reuse"))

	authSvc, _ := newAuth()
	wh := webhook.NewService(testPool)
	authSvc.SetEmitter(wh.Enqueue)
	subscribeTo(t, ctx, wh, tenantID, []string{"session.revoked"})

	pair, _ := tenantScopedSession(t, ctx, authSvc, tenantID)

	rotated, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Reusing the now-consumed original token trips theft detection.
	if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); err == nil {
		t.Fatal("reusing a consumed refresh token should fail")
	}
	_ = rotated

	deliveries := queuedDeliveries(t, ctx, tenantID, "session.revoked")
	if len(deliveries) != 1 {
		t.Fatalf("queued session.revoked deliveries = %d, want 1", len(deliveries))
	}
	if deliveries[0].Payload["reason"] != "reuse_detected" {
		t.Errorf("payload.reason = %v, want reuse_detected", deliveries[0].Payload["reason"])
	}
}

// TestRefresh_RejectsSuspendedOrDeletedUser closes the gap the CAEP work was
// scoped around: a session surviving a plain status change (no
// auth.sessions row is touched by PATCH /users/{id}) must not be able to
// keep minting fresh access tokens once the account is suspended or
// soft-deleted.
func TestRefresh_RejectsSuspendedOrDeletedUser(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("revoc-status"))
	authSvc, _ := newAuth()

	pairSuspended, userSuspended := tenantScopedSession(t, ctx, authSvc, tenantID)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, userSuspended); err != nil {
		t.Fatalf("suspend user: %v", err)
	}
	if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pairSuspended.RefreshToken}); err == nil {
		t.Fatal("refresh for a suspended user should fail")
	}

	pairDeleted, userDeleted := tenantScopedSession(t, ctx, authSvc, tenantID)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET deleted_at = NOW() WHERE id = $1`, userDeleted); err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}
	if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pairDeleted.RefreshToken}); err == nil {
		t.Fatal("refresh for a soft-deleted user should fail")
	}
}

// TestAssignUnassignRole_EmitsTokenClaimsChangeWebhook covers the second
// signal: a role grant/revoke changes what a user's already-issued access
// token is stale evidence of.
func TestAssignUnassignRole_EmitsTokenClaimsChangeWebhook(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("revoc-rbac"))
	userID := createUserInTenant(t, ctx, tenantID)

	repo := rbac.NewRepository(testPool)
	svc := rbac.NewService(repo)
	wh := webhook.NewService(testPool)
	svc.SetEmitter(wh.Enqueue)
	subscribeTo(t, ctx, wh, tenantID, []string{"token.claims_change"})

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	role, err := repo.CreateRole(ctx, tx, tenantID, "revoc-role-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := svc.AssignRole(ctx, userID, tenantID, role.ID, nil, audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := svc.UnassignRole(ctx, userID, tenantID, role.ID, audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("unassign role: %v", err)
	}

	deliveries := queuedDeliveries(t, ctx, tenantID, "token.claims_change")
	if len(deliveries) != 2 {
		t.Fatalf("queued token.claims_change deliveries = %d, want 2 (%+v)", len(deliveries), deliveries)
	}
	if deliveries[0].Payload["change"] != "role_assigned" || deliveries[1].Payload["change"] != "role_unassigned" {
		t.Errorf("deliveries = %+v, want [role_assigned, role_unassigned] in order", deliveries)
	}
}
