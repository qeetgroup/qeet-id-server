//go:build integration

package agent

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAgentsStayInTheirOrganization checks that one organization can neither read nor
// change another organization's agent, nor make another organization's user its sponsor,
// and that its kill switch stops only its own agents. An organization's own account
// sponsors without holding a role.
func TestAgentsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	sponsorA := dbtest.User(t, organizationA)
	adminB := dbtest.User(t, organizationB, organizationB)
	agentA, err := svc.Create(ctx, organizationA, "triage-bot", nil, 0, sponsorA.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	inB := "/organizations/" + organizationB.String() + "/agents"
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, inB + "/" + agentA.ID.String() + "/suspend", nil, http.StatusNotFound},
		{http.MethodPost, inB + "/" + agentA.ID.String() + "/decommission", nil, http.StatusNotFound},
		{http.MethodPatch, inB + "/" + agentA.ID.String(), map[string]any{"disabled": true}, http.StatusNotFound},
		{http.MethodDelete, inB + "/" + agentA.ID.String(), nil, http.StatusNotFound},
		{http.MethodPost, inB, map[string]any{"name": "b-bot", "sponsor_user_id": sponsorA.ID}, http.StatusUnprocessableEntity},
		{http.MethodPost, inB + "/sponsored-by/" + sponsorA.ID.String() + "/transfer", map[string]any{"to_user_id": adminB.ID}, http.StatusOK},
		{http.MethodPost, inB + "/kill-all", nil, http.StatusOK},
		{http.MethodGet, "/organizations/" + organizationA.String() + "/agents", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB, nil)); slices.Contains(ids, agentA.ID) {
		t.Error("organization B's agent list includes organization A's agent")
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB+"/sponsored-by/"+sponsorA.ID.String(), nil)); len(ids) != 0 {
		t.Errorf("organization B sees %d agents sponsored by organization A's user", len(ids))
	}

	if n := dbtest.Count(t, `
		SELECT count(*) FROM auth.agents WHERE id = $1 AND status = 'active' AND sponsor_user_id = $2
	`, agentA.ID, sponsorA.ID); n != 1 {
		t.Error("organization B changed organization A's agent")
	}
	if _, _, err := svc.ClientCredentials(ctx, agentA.ID.String(), agentA.Secret); err != nil {
		t.Errorf("organization A's agent can't get a token after organization B's calls: %v", err)
	}
}

// TestTokenChecksTheSecretFirst checks that a suspended agent's status is told
// only to a caller with its secret; a wrong secret gets the usual refusal.
func TestTokenChecksTheSecretFirst(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	sponsor := dbtest.User(t, organization, organization)
	a, err := svc.Create(ctx, organization, "batch-bot", nil, 0, sponsor.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, organization, "suspended", audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, _, err := svc.ClientCredentials(ctx, a.ID.String(), "wrong-secret"); !errors.Is(err, errs.ErrAgentTokenInvalid) {
		t.Errorf("wrong secret for a suspended agent: %v, want %v", err, errs.ErrAgentTokenInvalid)
	}
	if _, _, err := svc.ClientCredentials(ctx, a.ID.String(), a.Secret); !errors.Is(err, errs.ErrAgentInactive) {
		t.Errorf("right secret for a suspended agent: %v, want %v", err, errs.ErrAgentInactive)
	}
}

// TestAgentOfDeletedOrganizationIsRefused checks that an agent of a suspended
// or deleted organization gets no token, its right secret included, and that
// the tokens it was already issued stop: its status is no longer active.
// Reactivating the organization restores both.
func TestAgentOfDeletedOrganizationIsRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	sponsor := dbtest.User(t, organization, organization)
	a, err := svc.Create(ctx, organization, "batch-bot", nil, 0, sponsor.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	for _, step := range []struct {
		name, change string
		works        bool
	}{
		{"suspended", `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE organization.organizations SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE organization.organizations SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, organization); err != nil {
			t.Fatal(err)
		}
		if tok, known, err := svc.ClientCredentials(ctx, a.ID.String(), a.Secret); (err == nil && known && tok != nil) != step.works || known != step.works {
			t.Errorf("a token for an agent of a %s organization: known %v, %v; want works=%v", step.name, known, err, step.works)
		}
		if status, _ := svc.AgentStatus(ctx, a.ID); (status == "active") != step.works {
			t.Errorf("an issued token of a %s organization's agent: status %q, want active=%v", step.name, status, step.works)
		}
	}
}

// TestAgentsCarryOnlyTheCreatorsAuthority checks that a credential is created
// only with scopes its creator holds: a developer can't mint one with role.write.
func TestAgentsCarryOnlyTheCreatorsAuthority(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: NewService(pool, dbtest.Issuer(t)), GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	path := "/organizations/" + organization.String() + "/agents"

	body := func(scopes ...string) map[string]any {
		return map[string]any{"name": "ci-deploy", "scopes": scopes, "sponsor_user_id": developer.ID}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read", "role.write")); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) || !strings.Contains(rec.Body.String(), "role.write") {
		t.Errorf("create with role.write: %d %s, want 403 %s naming role.write", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read")); rec.Code != http.StatusCreated {
		t.Errorf("create with the creator's own scope: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.agents WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d credentials stored, want only the permitted one", n)
	}
}
