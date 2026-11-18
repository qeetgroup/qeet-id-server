//go:build integration

package servicehealth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestReportJudgesEachComponentByTheOrganization checks that a component
// unused by the organization is not configured, that failing webhooks and
// emails make theirs degraded for their organization only, that an open
// incident sets its component and the status, and that a resolved one is
// listed without doing so.
func TestReportJudgesEachComponentByTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	if _, err := pool.Exec(ctx, `TRUNCATE platform.incidents`); err != nil {
		t.Fatal(err)
	}

	rep, err := svc.Report(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ComponentAPI: StateOperational, ComponentSignIn: StateOperational, ComponentEmail: StateOperational,
		ComponentWebhooks: StateNotConfigured, ComponentDirectory: StateNotConfigured}
	if got := states(rep); !maps.Equal(got, want) || rep.Status != StateOperational {
		t.Errorf("a new organization: %v, status %s; want %v, operational", got, rep.Status, want)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.webhook_subscriptions (organization_id, url, secret_ct, secret_nonce, events, failing_since)
		VALUES ($1, 'https://hooks.example.com/a', '\x00', '\x00', '{user.created}', NOW() - INTERVAL '1 hour')`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO platform.email_messages (organization_id, to_hash, to_hint, provider, status)
		VALUES ($1, 'h1', 'a***@example.com', 'smtp', 'failed'), ($1, 'h2', 'b***@example.com', 'smtp', 'sent')`, organization); err != nil {
		t.Fatal(err)
	}
	rep, err = svc.Report(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	got := states(rep)
	if got[ComponentWebhooks] != StateDegraded || got[ComponentEmail] != StateDegraded || rep.Status != StateDegraded {
		t.Errorf("failing webhooks and emails: %v, status %s; want both degraded", got, rep.Status)
	}
	if rep, err := svc.Report(ctx, other); err != nil || rep.Status != StateOperational {
		t.Errorf("another organization: %+v, %v; want operational", rep, err)
	}

	resolved, err := svc.OpenIncident(ctx, ComponentDirectory, StateMaintenance, "Directory upgrade", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ResolveIncident(ctx, resolved); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResolveIncident(ctx, resolved); err == nil {
		t.Error("an incident was resolved twice")
	}
	if _, err := svc.OpenIncident(ctx, ComponentSignIn, StateOutage, "Sign-in is failing", "We are looking into it."); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.OpenIncident(ctx, "billing", StateOutage, "x", ""); err == nil {
		t.Error("an incident on an unknown component was opened")
	}
	rep, err = svc.Report(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	got = states(rep)
	if got[ComponentSignIn] != StateOutage || got[ComponentDirectory] != StateNotConfigured || rep.Status != StateOutage || len(rep.Incidents) != 2 {
		t.Errorf("with an open and a resolved incident: %v, status %s, %d incidents; want sign_in outage, 2 incidents", got, rep.Status, len(rep.Incidents))
	}

	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	if rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+other.String()+"/service-health", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization's health: %d, want 403", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/service-health", nil); rec.Code != http.StatusOK {
		t.Errorf("its own health: %d %s", rec.Code, rec.Body.String())
	}

	svc.SignInReady = func(context.Context) error { return errors.New("no signing key") }
	if rep, err := svc.Report(ctx, organization); err != nil || states(rep)[ComponentSignIn] != StateOutage {
		t.Errorf("without a signing key: %+v, %v; want sign_in outage", rep, err)
	}
}

func states(r *Report) map[string]string {
	out := map[string]string{}
	for _, c := range r.Components {
		out[c.Name] = c.State
	}
	return out
}
