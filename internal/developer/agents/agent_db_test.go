//go:build integration

package agent

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAgentsStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's agent, nor make another tenant's user its sponsor,
// and that its kill switch stops only its own agents.
func TestAgentsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	sponsorA := dbtest.User(t, tenantA, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)
	agentA, err := svc.Create(ctx, tenantA, "triage-bot", nil, 0, sponsorA.ID, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("create agent in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
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
