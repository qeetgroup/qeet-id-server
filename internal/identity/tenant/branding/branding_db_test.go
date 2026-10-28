//go:build integration

package branding

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
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

// TestUploadedLogoIsServedForEmailsAndHostedPages checks that an uploaded logo
// (a data URL) reaches emails and hosted pages as this API's https link, that
// the link serves the image safely, and that a logo set by URL is left as is.
func TestUploadedLogoIsServedForEmailsAndHostedPages(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant, linked := dbtest.Tenant(t), dbtest.Tenant(t)
	repo := NewRepository(dbtest.Pool(t))
	repo.SetPublicBaseURL("https://api.example.test/")
	gate := &planGate{on: true}
	repo.SetPlanGate(gate)
	png := []byte("\x89PNG\r\n\x1a\nfake")
	uploaded := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	byURL := "https://cdn.example.test/logo.png"
	save := func(id uuid.UUID, logo string) {
		tx, err := dbtest.Pool(t).Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Upsert(ctx, tx, Branding{TenantID: id, LogoURL: &logo}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	save(tenant, uploaded)
	save(linked, byURL)

	want := "https://api.example.test/v1/branding/" + tenant.String() + "/logo?v="
	if l, _, _, _ := repo.LoginBranding(ctx, tenant); !strings.HasPrefix(l, want) {
		t.Errorf("hosted pages get %q, want a link starting %q", l, want)
	}
	if _, l, _, _ := repo.EmailAppearance(ctx, tenant); !strings.HasPrefix(l, want) {
		t.Errorf("emails get %q, want a link starting %q", l, want)
	}
	if l, _, _, _ := repo.LoginBranding(ctx, linked); l != byURL {
		t.Errorf("a logo set by URL reaches hosted pages as %q, want it unchanged", l)
	}

	router := chi.NewRouter()
	(&Handler{Repo: repo}).MountPublic(router)
	get := func(id uuid.UUID) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/branding/"+id.String()+"/logo?v=1", nil))
		return rec
	}
	rec := get(tenant)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), png) || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("the logo: %d %q %q, want the uploaded PNG", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("served without nosniff and a sandboxing CSP: %v", rec.Header())
	}
	if rec := get(linked); rec.Code != http.StatusNotFound {
		t.Errorf("an organisation whose logo is a URL: %d, want 404", rec.Code)
	}
	gate.on = false
	if rec := get(tenant); rec.Code != http.StatusNotFound {
		t.Errorf("without custom_branding: %d, want 404", rec.Code)
	}
}
