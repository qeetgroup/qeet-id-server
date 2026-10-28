//go:build integration

package branding

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// planGate allows custom branding when on.
type planGate struct{ on bool }

func (g *planGate) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return g.on, nil }

// TestBrandingFollowsThePlan checks that the hosted pages and emails show an
// organisation's branding only while its plan includes custom branding, and
// that the stored branding comes back on an upgrade.
func TestBrandingFollowsThePlan(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	repo := NewRepository(dbtest.Pool(t))
	logo, primary, name := "https://cdn.example.test/acme.png", "#112233", "Acme"
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Upsert(ctx, tx, Branding{TenantID: tenant, LogoURL: &logo, PrimaryColor: &primary, EmailFromName: &name}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	gate := &planGate{on: true}
	repo.SetPlanGate(gate)
	if l, p, _, _ := repo.LoginBranding(ctx, tenant); l != logo || p != primary {
		t.Errorf("on a plan with branding the hosted pages get %q %q, want the stored logo and colour", l, p)
	}
	gate.on = false
	if l, p, s, b := repo.LoginBranding(ctx, tenant); l != "" || p != "" || s != "" || b != "" {
		t.Errorf("without custom_branding the hosted pages get %q %q %q %q, want the default look", l, p, s, b)
	}
	if n, l, p, err := repo.EmailAppearance(ctx, tenant); err != nil || n != "" || l != "" || p != "" {
		t.Errorf("without custom_branding emails get %q %q %q (%v), want the default look", n, l, p, err)
	}
	gate.on = true
	if n, l, _, err := repo.EmailAppearance(ctx, tenant); err != nil || n != name || l != logo {
		t.Errorf("after an upgrade emails get %q %q (%v), want the stored branding back", n, l, err)
	}
}
