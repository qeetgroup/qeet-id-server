//go:build integration

package agent

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRotatingAnAgentNeedsItsScopes checks that rotating an agent's secret
// hands its scopes to whoever rotates it, so it is held to the rule for
// creating one: a developer can't rotate one carrying role.write, and its
// secret stays as it was, while one carrying only their own scopes rotates.
func TestRotatingAnAgentNeedsItsScopes(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	svc := NewService(pool, dbtest.Issuer(t))
	create := func(scopes ...string) uuid.UUID {
		t.Helper()
		a, err := svc.Create(ctx, organization, dbtest.Unique("agent"), scopes, 0, developer.ID, audit.Actor{UserID: &developer.ID, Type: "user"})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	secret := func(id uuid.UUID) string {
		t.Helper()
		var hash string
		if err := pool.QueryRow(ctx, `SELECT secret_hash FROM auth.agents WHERE organization_id = $1 AND id = $2`, organization, id).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: svc, GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	rotate := func(id uuid.UUID) (int, string) {
		rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/agents/"+id.String()+"/rotate-secret", nil)
		return rec.Code, rec.Body.String()
	}

	powerful := create("user.read", "role.write")
	before := secret(powerful)
	if status, body := rotate(powerful); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACGrantExceedsCaller) || strings.Contains(body, `"secret"`) {
		t.Errorf("rotate an agent carrying role.write: %d %s, want 403 %s and no secret", status, body, errs.CodeRBACGrantExceedsCaller)
	}
	if secret(powerful) != before {
		t.Error("the refused rotation changed the agent's secret")
	}
	if status, body := rotate(create("user.read")); status != http.StatusOK {
		t.Errorf("rotate an agent carrying only the developer's scope: %d %s, want 200", status, body)
	}
}

// TestAgentSecretsRotateAndAgentsResumeTogether checks that a rotated agent's
// old secret goes on minting tokens until its overlap ends, that a token
// minted is noted as its last use, and that resume-all undoes the kill switch
// for its own organization only.
func TestAgentSecretsRotateAndAgentsResumeTogether(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	system := audit.Actor{Type: "system"}
	a, err := svc.Create(ctx, organization, "triage-bot", nil, 0, dbtest.User(t, organization, organization).ID, system)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Create(ctx, other, "other-bot", nil, 0, dbtest.User(t, other, other).ID, system)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := svc.RotateSecret(ctx, organization, a.ID, time.Hour, system)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for name, s := range map[string]string{"old": a.Secret, "new": secret} {
		if _, known, err := svc.ClientCredentials(ctx, a.ID.String(), s); err != nil || !known {
			t.Errorf("the %s secret during the overlap: known %v, %v", name, known, err)
		}
	}
	list, err := svc.List(ctx, organization)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil || list[0].PreviousSecretExpiresAt == nil {
		t.Errorf("listed agents %+v, %v: want a last use and the overlap's end", list, err)
	}
	if _, _, err := svc.RotateSecret(ctx, organization, a.ID, 0, system); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ClientCredentials(ctx, a.ID.String(), secret); !errors.Is(err, errs.ErrAgentTokenInvalid) {
		t.Errorf("a secret rotated with no overlap: %v, want %v", err, errs.ErrAgentTokenInvalid)
	}
	if _, _, err := svc.RotateSecret(ctx, other, a.ID, time.Hour, system); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate from another organization: %v, want %v", err, ErrNotFound)
	}

	for _, tid := range []uuid.UUID{organization, other} {
		if _, err := svc.KillAll(ctx, tid, system); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := svc.ResumeAll(ctx, organization, system); err != nil || n != 1 {
		t.Errorf("resume all: %d, %v; want 1", n, err)
	}
	for id, want := range map[uuid.UUID]string{a.ID: "active", b.ID: "suspended"} {
		if got, err := svc.AgentStatus(ctx, id); err != nil || got != want {
			t.Errorf("agent %s after resume-all: %q, %v; want %q", id, got, err, want)
		}
	}
}
