//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	agent "github.com/qeetgroup/qeet-id-server/internal/developer/agents"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// addTenantMember grants userID a role in tenantID directly (bypassing the
// invite flow), so the agent sponsor checks — which key off rbac.user_roles
// membership, not the user's "home" tenant_id — see a real member.
func addTenantMember(t *testing.T, ctx context.Context, tenantID, userID uuid.UUID) {
	t.Helper()
	var roleID uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'member')
		ON CONFLICT (tenant_id, (LOWER(name))) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`, tenantID).Scan(&roleID)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, userID, tenantID, roleID); err != nil {
		t.Fatalf("add member: %v", err)
	}
}

func createUserIn(t *testing.T, ctx context.Context, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("agentowner")+"@example.com").Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

// Agent sponsor model: creation requires a sponsor who's an actual tenant
// member, and TransferSponsor reassigns every agent an offboarding sponsor
// owned to their replacement in one call.
func TestAgentSponsorRequiredAndTransferable(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("agent"))
	svc := agent.NewService(testPool, mustIssuer())

	sponsor := createUserIn(t, ctx, tenantID)
	addTenantMember(t, ctx, tenantID, sponsor)

	// No sponsor at all — rejected.
	if _, err := svc.Create(ctx, tenantID, "no-sponsor", nil, 0, uuid.Nil); err == nil {
		t.Fatal("Create without a sponsor should fail")
	}

	// A user who exists but isn't a member of this tenant — rejected.
	outsider := createUserIn(t, ctx, tenantID) // created "in" tenantID's users table, but never granted membership
	if _, err := svc.Create(ctx, tenantID, "outsider-sponsor", nil, 0, outsider); err == nil {
		t.Fatal("Create with a non-member sponsor should fail")
	}

	a1, err := svc.Create(ctx, tenantID, "agent-one", []string{"users:read"}, 0, sponsor)
	if err != nil {
		t.Fatalf("create agent-one: %v", err)
	}
	if a1.SponsorUserID == nil || *a1.SponsorUserID != sponsor {
		t.Fatalf("agent-one sponsor = %v, want %v", a1.SponsorUserID, sponsor)
	}
	if _, err := svc.Create(ctx, tenantID, "agent-two", nil, 0, sponsor); err != nil {
		t.Fatalf("create agent-two: %v", err)
	}

	sponsored, err := svc.AgentsSponsoredBy(ctx, tenantID, sponsor)
	if err != nil {
		t.Fatalf("agents sponsored by: %v", err)
	}
	if len(sponsored) != 2 {
		t.Fatalf("sponsored count = %d, want 2", len(sponsored))
	}

	// Offboard the sponsor: transfer everything they sponsored to a replacement.
	replacement := createUserIn(t, ctx, tenantID)
	addTenantMember(t, ctx, tenantID, replacement)
	n, err := svc.TransferSponsor(ctx, tenantID, sponsor, replacement)
	if err != nil {
		t.Fatalf("transfer sponsor: %v", err)
	}
	if n != 2 {
		t.Fatalf("transferred = %d, want 2", n)
	}

	nowEmpty, err := svc.AgentsSponsoredBy(ctx, tenantID, sponsor)
	if err != nil || len(nowEmpty) != 0 {
		t.Fatalf("sponsor should own nothing after transfer, got %v (err %v)", nowEmpty, err)
	}
	nowOwned, err := svc.AgentsSponsoredBy(ctx, tenantID, replacement)
	if err != nil || len(nowOwned) != 2 {
		t.Fatalf("replacement should own 2 agents after transfer, got %v (err %v)", nowOwned, err)
	}

	// Transferring to a non-member is rejected, with a typed errs.Error.
	_, transferErr := svc.TransferSponsor(ctx, tenantID, replacement, outsider)
	if transferErr == nil {
		t.Fatal("TransferSponsor to a non-member should fail")
	}
	if e := errs.As(transferErr); e == nil {
		t.Fatalf("expected a typed errs.Error, got %v", transferErr)
	}
}
