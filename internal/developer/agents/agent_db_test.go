//go:build integration

package agent

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAgentsStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's agent, nor make another tenant's user its sponsor,
// and that its kill switch stops only its own agents. A tenant's own account
// sponsors without holding a role.
func TestAgentsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	sponsorA := dbtest.User(t, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)
	agentA, err := svc.Create(ctx, tenantA, "triage-bot", nil, 0, sponsorA.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	inB := "/tenants/" + tenantB.String() + "/agents"
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
		{http.MethodGet, "/tenants/" + tenantA.String() + "/agents", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB, nil)); slices.Contains(ids, agentA.ID) {
		t.Error("tenant B's agent list includes tenant A's agent")
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB+"/sponsored-by/"+sponsorA.ID.String(), nil)); len(ids) != 0 {
		t.Errorf("tenant B sees %d agents sponsored by tenant A's user", len(ids))
	}

	if n := dbtest.Count(t, `
		SELECT count(*) FROM auth.agents WHERE id = $1 AND status = 'active' AND sponsor_user_id = $2
	`, agentA.ID, sponsorA.ID); n != 1 {
		t.Error("tenant B changed tenant A's agent")
	}
	if _, err := svc.IssueToken(ctx, agentA.ID.String(), agentA.Secret); err != nil {
		t.Errorf("tenant A's agent can't get a token after tenant B's calls: %v", err)
	}
}

// TestTokenChecksTheSecretFirst checks that a suspended agent's status is told
// only to a caller with its secret; a wrong secret gets the usual refusal.
func TestTokenChecksTheSecretFirst(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	sponsor := dbtest.User(t, tenant, tenant)
	a, err := svc.Create(ctx, tenant, "batch-bot", nil, 0, sponsor.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, tenant, "suspended", audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := svc.IssueToken(ctx, a.ID.String(), "wrong-secret"); !errors.Is(err, errs.ErrAgentTokenInvalid) {
		t.Errorf("wrong secret for a suspended agent: %v, want %v", err, errs.ErrAgentTokenInvalid)
	}
	if _, err := svc.IssueToken(ctx, a.ID.String(), a.Secret); !errors.Is(err, errs.ErrAgentInactive) {
		t.Errorf("right secret for a suspended agent: %v, want %v", err, errs.ErrAgentInactive)
	}
}

// TestAgentSecretsRotateAndAgentsResumeTogether checks that a rotated agent's
// old secret goes on minting tokens until its overlap ends, that a token
// minted is noted as its last use, and that resume-all undoes the kill switch
// for its own tenant only.
func TestAgentSecretsRotateAndAgentsResumeTogether(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	system := audit.Actor{Type: "system"}
	a, err := svc.Create(ctx, tenant, "triage-bot", nil, 0, dbtest.User(t, tenant, tenant).ID, system)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Create(ctx, other, "other-bot", nil, 0, dbtest.User(t, other, other).ID, system)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := svc.RotateSecret(ctx, tenant, a.ID, time.Hour, system)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for name, s := range map[string]string{"old": a.Secret, "new": secret} {
		if _, err := svc.IssueToken(ctx, a.ID.String(), s); err != nil {
			t.Errorf("the %s secret during the overlap: %v", name, err)
		}
	}
	list, err := svc.List(ctx, tenant)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil || list[0].PreviousSecretExpiresAt == nil {
		t.Errorf("listed agents %+v, %v: want a last use and the overlap's end", list, err)
	}
	if _, _, err := svc.RotateSecret(ctx, tenant, a.ID, 0, system); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IssueToken(ctx, a.ID.String(), secret); !errors.Is(err, errs.ErrAgentTokenInvalid) {
		t.Errorf("a secret rotated with no overlap: %v, want %v", err, errs.ErrAgentTokenInvalid)
	}
	if _, _, err := svc.RotateSecret(ctx, other, a.ID, time.Hour, system); !errors.Is(err, errs.ErrAgentNotFound) {
		t.Errorf("rotate from another tenant: %v, want %v", err, errs.ErrAgentNotFound)
	}

	for _, tid := range []uuid.UUID{tenant, other} {
		if _, err := svc.KillAll(ctx, tid, system); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := svc.ResumeAll(ctx, tenant, system); err != nil || n != 1 {
		t.Errorf("resume all: %d, %v; want 1", n, err)
	}
	for id, want := range map[uuid.UUID]string{a.ID: "active", b.ID: "suspended"} {
		if got, err := svc.AgentStatus(ctx, id); err != nil || got != want {
			t.Errorf("agent %s after resume-all: %q, %v; want %q", id, got, err, want)
		}
	}
}

// TestAgentOfDeletedOrganisationIsRefused checks that an agent of a suspended
// or deleted organisation gets no token, its right secret included, and that
// the tokens it was already issued stop: its status is no longer active.
// Reactivating the organisation restores both.
func TestAgentOfDeletedOrganisationIsRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	sponsor := dbtest.User(t, tenant, tenant)
	a, err := svc.Create(ctx, tenant, "batch-bot", nil, 0, sponsor.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	for _, step := range []struct {
		name, change string
		works        bool
	}{
		{"suspended", `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE tenant.tenants SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE tenant.tenants SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.IssueToken(ctx, a.ID.String(), a.Secret); (err == nil) != step.works {
			t.Errorf("a token for an agent of a %s organisation: %v, want works=%v", step.name, err, step.works)
		}
		if status, _ := svc.AgentStatus(ctx, a.ID); (status == "active") != step.works {
			t.Errorf("an issued token of a %s organisation's agent: status %q, want active=%v", step.name, status, step.works)
		}
	}
}
