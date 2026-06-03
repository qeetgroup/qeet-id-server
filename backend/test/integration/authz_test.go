//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/gdpr"
	"github.com/qeetgroup/qeet-identity/internal/rbac"
)

func createUserInTenant(t *testing.T, ctx context.Context, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("u")+"@example.com").Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

// TestRBACDecisionMatrix exercises the authorization hot path: a granted
// permission is allowed; an ungranted one is denied; permissions never cross
// tenants; and an unassigned user is denied.
func TestRBACDecisionMatrix(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := rbac.NewRepository(testPool)

	tenantA := createTenant(t, ctx, uniqueSlug("rbac-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("rbac-b"))
	user := createUserInTenant(t, ctx, tenantA)
	other := createUserInTenant(t, ctx, tenantA)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	perm, err := repo.UpsertPermission(ctx, tx, "billing:write", "write billing")
	if err != nil {
		t.Fatalf("permission: %v", err)
	}
	if _, err := repo.UpsertPermission(ctx, tx, "billing:read", "read billing"); err != nil {
		t.Fatalf("permission2: %v", err)
	}
	role, err := repo.CreateRole(ctx, tx, tenantA, "biller-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	if err := repo.GrantPermission(ctx, tx, role.ID, perm.ID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := repo.AssignRole(ctx, tx, user, tenantA, role.ID, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	check := func(u, tn uuid.UUID, p string) bool {
		ok, err := repo.Check(ctx, u, tn, p)
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		return ok
	}

	if !check(user, tenantA, "billing:write") {
		t.Error("granted permission should be allowed")
	}
	if check(user, tenantA, "billing:read") {
		t.Error("ungranted permission must be denied")
	}
	if check(user, tenantB, "billing:write") {
		t.Error("permission must not cross tenants (isolation)")
	}
	if check(other, tenantA, "billing:write") {
		t.Error("unassigned user must be denied")
	}

	perms, err := repo.EffectivePermissions(ctx, user, tenantA)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if len(perms) != 1 || perms[0] != "billing:write" {
		t.Errorf("effective permissions = %v, want [billing:write]", perms)
	}
}

// TestGDPRErasure verifies right-to-erasure: PII is redacted and credentials are
// dropped, but the user row is retained (so audit references stay valid) and the
// request is marked completed.
func TestGDPRErasure(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("gdpr"))
	user := createUserInTenant(t, ctx, tenantID)

	if _, err := testPool.Exec(ctx,
		`UPDATE "user".users SET display_name = 'Jane Doe', phone = '+15555550100' WHERE id = $1`, user); err != nil {
		t.Fatalf("set pii: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`,
		user, "$2a$10$0123456789012345678901uVx/ placeholder"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	svc := gdpr.NewService(testPool, time.Hour)
	req, err := svc.Request(ctx, gdpr.CreateInput{TenantID: tenantID, UserID: user, Reason: "user requested"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Force the grace window into the past so the request is ripe.
	if _, err := testPool.Exec(ctx,
		`UPDATE "user".purge_requests SET grace_until = NOW() - INTERVAL '1 hour' WHERE id = $1`, req.ID); err != nil {
		t.Fatalf("expire grace: %v", err)
	}

	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// User row retained, PII redacted.
	var email, status string
	var displayName, phone *string
	if err := testPool.QueryRow(ctx,
		`SELECT email, status, display_name, phone FROM "user".users WHERE id = $1`, user).
		Scan(&email, &status, &displayName, &phone); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !strings.HasPrefix(email, "redacted-") || !strings.HasSuffix(email, "@gdpr.invalid") {
		t.Errorf("email not redacted: %q", email)
	}
	if status != "deleted" {
		t.Errorf("status = %q, want deleted", status)
	}
	if displayName != nil || phone != nil {
		t.Errorf("display_name/phone should be cleared: %v / %v", displayName, phone)
	}

	// Credentials dropped.
	var creds int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`, user).Scan(&creds); err != nil {
		t.Fatalf("count creds: %v", err)
	}
	if creds != 0 {
		t.Errorf("password credentials should be deleted, got %d", creds)
	}

	// Request marked completed.
	var reqStatus string
	if err := testPool.QueryRow(ctx,
		`SELECT status FROM "user".purge_requests WHERE id = $1`, req.ID).Scan(&reqStatus); err != nil {
		t.Fatalf("read request: %v", err)
	}
	if reqStatus != "completed" {
		t.Errorf("request status = %q, want completed", reqStatus)
	}
}
