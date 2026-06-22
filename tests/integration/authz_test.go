//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id/domains/operations/compliance"
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

// createGroup inserts a bare group row and returns its id.
func createGroup(t *testing.T, ctx context.Context, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id
	`, tenantID, name).Scan(&id); err != nil {
		t.Fatalf("create group: %v", err)
	}
	return id
}

func addGroupMember(t *testing.T, ctx context.Context, groupID, userID, tenantID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)
	`, groupID, userID, tenantID); err != nil {
		t.Fatalf("add group member: %v", err)
	}
}

// TestRBACGroupRolesMatrix exercises group-level roles: a role granted to a
// group confers its permission on members; revoking the group-role or removing
// the membership revokes it; direct + group grants union correctly; and none of
// it crosses tenants.
func TestRBACGroupRolesMatrix(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := rbac.NewRepository(testPool)

	tenantA := createTenant(t, ctx, uniqueSlug("grp-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("grp-b"))
	member := createUserInTenant(t, ctx, tenantA)   // gets the role only via the group
	outsider := createUserInTenant(t, ctx, tenantA) // in the tenant, not in the group

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	deployPerm, err := repo.UpsertPermission(ctx, tx, "deploy:write", "write deploy")
	if err != nil {
		t.Fatalf("permission: %v", err)
	}
	if _, err := repo.UpsertPermission(ctx, tx, "deploy:read", "read deploy"); err != nil {
		t.Fatalf("permission2: %v", err)
	}
	role, err := repo.CreateRole(ctx, tx, tenantA, "deployer-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	if err := repo.GrantPermission(ctx, tx, role.ID, deployPerm.ID); err != nil {
		t.Fatalf("grant perm: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	group := createGroup(t, ctx, tenantA, "Engineering")
	addGroupMember(t, ctx, group, member, tenantA)

	check := func(u, tn uuid.UUID, p string) bool {
		ok, err := repo.Check(ctx, u, tn, p)
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		return ok
	}

	// Before the group-role grant: member has nothing.
	if check(member, tenantA, "deploy:write") {
		t.Error("member must not have permission before the group-role grant")
	}

	// Grant the role to the group.
	gtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin grant-to-group: %v", err)
	}
	valid, err := repo.AssignRoleToGroup(ctx, gtx, group, tenantA, role.ID, nil)
	if err != nil {
		t.Fatalf("assign role to group: %v", err)
	}
	if !valid {
		t.Fatal("AssignRoleToGroup reported invalid for a same-tenant group+role")
	}
	if err := gtx.Commit(ctx); err != nil {
		t.Fatalf("commit grant-to-group: %v", err)
	}

	// Group member inherits the permission; an ungranted perm is still denied.
	if !check(member, tenantA, "deploy:write") {
		t.Error("group member should inherit the group-role's permission")
	}
	if check(member, tenantA, "deploy:read") {
		t.Error("ungranted permission must be denied even via group")
	}
	// A non-member in the same tenant gets nothing from the group.
	if check(outsider, tenantA, "deploy:write") {
		t.Error("non-member must not inherit the group-role")
	}
	// Group-derived permission must not cross tenants.
	if check(member, tenantB, "deploy:write") {
		t.Error("group-derived permission must not cross tenants (isolation)")
	}

	// Effective permissions surface the group-derived perm.
	perms, err := repo.EffectivePermissions(ctx, member, tenantA)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if len(perms) != 1 || perms[0] != "deploy:write" {
		t.Errorf("effective permissions via group = %v, want [deploy:write]", perms)
	}

	// Direct + group union: also grant the member a direct role with a second
	// permission and confirm both surface, deduplicated.
	dtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin direct: %v", err)
	}
	directPerm, err := repo.UpsertPermission(ctx, dtx, "deploy:read", "read deploy")
	if err != nil {
		t.Fatalf("direct perm: %v", err)
	}
	directRole, err := repo.CreateRole(ctx, dtx, tenantA, "reader-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("direct role: %v", err)
	}
	if err := repo.GrantPermission(ctx, dtx, directRole.ID, directPerm.ID); err != nil {
		t.Fatalf("grant direct perm: %v", err)
	}
	if err := repo.AssignRole(ctx, dtx, member, tenantA, directRole.ID, nil); err != nil {
		t.Fatalf("assign direct: %v", err)
	}
	if err := dtx.Commit(ctx); err != nil {
		t.Fatalf("commit direct: %v", err)
	}
	perms, err = repo.EffectivePermissions(ctx, member, tenantA)
	if err != nil {
		t.Fatalf("effective union: %v", err)
	}
	if len(perms) != 2 || perms[0] != "deploy:read" || perms[1] != "deploy:write" {
		t.Errorf("union effective = %v, want [deploy:read deploy:write]", perms)
	}

	// Removing the membership revokes the group-derived perm (the direct one
	// stays).
	if _, err := testPool.Exec(ctx,
		`DELETE FROM tenant.group_members WHERE group_id = $1 AND user_id = $2`, group, member); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if check(member, tenantA, "deploy:write") {
		t.Error("removing group membership must revoke the group-derived permission")
	}
	if !check(member, tenantA, "deploy:read") {
		t.Error("direct grant must survive group-membership removal")
	}

	// Re-add the member, then revoke the group-role itself: also revokes it.
	addGroupMember(t, ctx, group, member, tenantA)
	if !check(member, tenantA, "deploy:write") {
		t.Error("re-adding member should restore the group-derived permission")
	}
	rtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revoke: %v", err)
	}
	if err := repo.RemoveRoleFromGroup(ctx, rtx, group, tenantA, role.ID); err != nil {
		t.Fatalf("remove role from group: %v", err)
	}
	if err := rtx.Commit(ctx); err != nil {
		t.Fatalf("commit revoke: %v", err)
	}
	if check(member, tenantA, "deploy:write") {
		t.Error("revoking the group-role must revoke the group-derived permission")
	}
}

// TestRBACExplain verifies the explainable-authorization resolver names the
// correct grant path for a direct grant, a group-derived grant, and a denial.
func TestRBACExplain(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := rbac.NewRepository(testPool)

	tenantA := createTenant(t, ctx, uniqueSlug("exp-a"))
	user := createUserInTenant(t, ctx, tenantA)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	perm, err := repo.UpsertPermission(ctx, tx, "report:read", "read report")
	if err != nil {
		t.Fatalf("permission: %v", err)
	}
	directRole, err := repo.CreateRole(ctx, tx, tenantA, "admin-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("direct role: %v", err)
	}
	groupRole, err := repo.CreateRole(ctx, tx, tenantA, "viewer-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("group role: %v", err)
	}
	if err := repo.GrantPermission(ctx, tx, directRole.ID, perm.ID); err != nil {
		t.Fatalf("grant direct: %v", err)
	}
	if err := repo.GrantPermission(ctx, tx, groupRole.ID, perm.ID); err != nil {
		t.Fatalf("grant group: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Denial path: no grants yet.
	exp, err := repo.Explain(ctx, user, tenantA, "report:read")
	if err != nil {
		t.Fatalf("explain deny: %v", err)
	}
	if exp.Allowed || len(exp.Paths) != 0 || exp.Reason == "" {
		t.Errorf("denied explain = %+v, want allowed=false, no paths, a reason", exp)
	}

	// Direct grant: one path, via "direct".
	atx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin assign: %v", err)
	}
	if err := repo.AssignRole(ctx, atx, user, tenantA, directRole.ID, nil); err != nil {
		t.Fatalf("assign direct: %v", err)
	}
	if err := atx.Commit(ctx); err != nil {
		t.Fatalf("commit assign: %v", err)
	}
	exp, err = repo.Explain(ctx, user, tenantA, "report:read")
	if err != nil {
		t.Fatalf("explain direct: %v", err)
	}
	if !exp.Allowed || len(exp.Paths) != 1 {
		t.Fatalf("direct explain = %+v, want allowed=true with 1 path", exp)
	}
	if exp.Paths[0].Via != "direct" || exp.Paths[0].GrantedBy != "role:"+directRole.Name {
		t.Errorf("direct path = %+v, want via=direct granted_by=role:%s", exp.Paths[0], directRole.Name)
	}
	if exp.Paths[0].GroupID != nil {
		t.Errorf("direct path should not carry a group_id, got %v", exp.Paths[0].GroupID)
	}

	// Add a group-derived grant for the SAME permission: now two paths, and one
	// of them names the group.
	group := createGroup(t, ctx, tenantA, "Auditors")
	addGroupMember(t, ctx, group, user, tenantA)
	gtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin group grant: %v", err)
	}
	if _, err := repo.AssignRoleToGroup(ctx, gtx, group, tenantA, groupRole.ID, nil); err != nil {
		t.Fatalf("assign role to group: %v", err)
	}
	if err := gtx.Commit(ctx); err != nil {
		t.Fatalf("commit group grant: %v", err)
	}
	exp, err = repo.Explain(ctx, user, tenantA, "report:read")
	if err != nil {
		t.Fatalf("explain both: %v", err)
	}
	if !exp.Allowed || len(exp.Paths) != 2 {
		t.Fatalf("union explain = %+v, want allowed=true with 2 paths", exp)
	}
	var sawDirect, sawGroup bool
	for _, p := range exp.Paths {
		switch p.Via {
		case "direct":
			sawDirect = true
		case "group:Auditors":
			sawGroup = true
			if p.GrantedBy != "role:"+groupRole.Name {
				t.Errorf("group path granted_by = %q, want role:%s", p.GrantedBy, groupRole.Name)
			}
			if p.GroupID == nil || *p.GroupID != group {
				t.Errorf("group path group_id = %v, want %v", p.GroupID, group)
			}
		default:
			t.Errorf("unexpected via %q", p.Via)
		}
	}
	if !sawDirect || !sawGroup {
		t.Errorf("explain paths = %+v, want both a direct and a group:Auditors path", exp.Paths)
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
