//go:build integration

package branding

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// planGate allows custom branding when on.
type planGate struct{ on bool }

func (g *planGate) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return g.on, nil }

// TestBrandingFollowsThePlan checks that the hosted pages and emails show an
// organization's branding only while its plan includes custom branding, and
// that the stored branding comes back on an upgrade.
func TestBrandingFollowsThePlan(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	repo := NewRepository(dbtest.Pool(t))
	logo, primary, name := "https://cdn.example.test/acme.png", "#112233", "Acme"
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.upsert(ctx, tx, Branding{OrganizationID: organization, LogoURL: &logo, PrimaryColor: &primary, EmailFromName: &name}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	gate := &planGate{on: true}
	repo.SetPlanGate(gate)
	if l, p, _, _ := repo.LoginBranding(ctx, organization); l != logo || p != primary {
		t.Errorf("on a plan with branding the hosted pages get %q %q, want the stored logo and colour", l, p)
	}
	gate.on = false
	if l, p, s, b := repo.LoginBranding(ctx, organization); l != "" || p != "" || s != "" || b != "" {
		t.Errorf("without custom_branding the hosted pages get %q %q %q %q, want the default look", l, p, s, b)
	}
	if n, l, p, err := repo.EmailAppearance(ctx, organization); err != nil || n != "" || l != "" || p != "" {
		t.Errorf("without custom_branding emails get %q %q %q (%v), want the default look", n, l, p, err)
	}
	gate.on = true
	if n, l, _, err := repo.EmailAppearance(ctx, organization); err != nil || n != name || l != logo {
		t.Errorf("after an upgrade emails get %q %q (%v), want the stored branding back", n, l, err)
	}
}

// TestUploadedLogoIsServedForEmailsAndHostedPages checks that an uploaded logo
// (a data URL) reaches emails and hosted pages as this API's https link, that
// the link serves the image safely, and that a logo set by URL is left as is.
func TestUploadedLogoIsServedForEmailsAndHostedPages(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, linked := dbtest.Organization(t), dbtest.Organization(t)
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
		if err := repo.upsert(ctx, tx, Branding{OrganizationID: id, LogoURL: &logo}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	save(organization, uploaded)
	save(linked, byURL)

	want := "https://api.example.test/v1/branding/" + organization.String() + "/logo?v="
	if l, _, _, _ := repo.LoginBranding(ctx, organization); !strings.HasPrefix(l, want) {
		t.Errorf("hosted pages get %q, want a link starting %q", l, want)
	}
	if _, l, _, _ := repo.EmailAppearance(ctx, organization); !strings.HasPrefix(l, want) {
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
	rec := get(organization)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), png) || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("the logo: %d %q %q, want the uploaded PNG", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("served without nosniff and a sandboxing CSP: %v", rec.Header())
	}
	if rec := get(linked); rec.Code != http.StatusNotFound {
		t.Errorf("an organization whose logo is a URL: %d, want 404", rec.Code)
	}
	gate.on = false
	if rec := get(organization); rec.Code != http.StatusNotFound {
		t.Errorf("without custom_branding: %d, want 404", rec.Code)
	}
}

// TestFromAddressIsNotKept checks that a sender address sent with the branding
// is ignored and never returned, while the accent colour reaches the hosted
// pages.
func TestFromAddressIsNotKept(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	repo := NewRepository(dbtest.Pool(t))
	from, accent := "noreply@acme.example", "#abcdef"
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.upsert(ctx, tx, Branding{OrganizationID: organization, EmailFromAddress: &from, SecondaryColor: &accent}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := repo.Get(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(b); b.EmailFromAddress != nil || strings.Contains(string(raw), "email_from_address") {
		t.Errorf("branding %s; want no sender address kept or returned", raw)
	}
	if _, _, secondary, _ := repo.LoginBranding(ctx, organization); secondary != accent {
		t.Errorf("the hosted pages get accent %q, want %q", secondary, accent)
	}
}

// TestSaveCommitsWithItsAuditRow checks that saving branding records
// branding.updated, with the actor's address, browser and request, and that a
// save the plan refuses stores nothing and records nothing.
func TestSaveCommitsWithItsAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	repo := NewRepository(dbtest.Pool(t))
	admin := uuid.New()
	actor := audit.Actor{UserID: &admin, Type: "user", IP: "198.51.100.11", UserAgent: "branding-test", RequestID: "req-branding"}
	recorded := func() int {
		return dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = 'branding.updated' AND resource_id = $1 AND actor_user_id = $2
			  AND host(ip) = $3 AND user_agent = $4 AND request_id = $5 AND metadata->>'primary_color' = '#445566'`,
			organization, admin, actor.IP, actor.UserAgent, actor.RequestID)
	}
	stored := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.branding WHERE organization_id = $1`, organization)
	}
	primary := "#445566"
	repo.SetPlanGate(&planGate{on: false})
	if err := repo.Save(ctx, Branding{OrganizationID: organization, PrimaryColor: &primary}, actor); err == nil {
		t.Fatal("a plan without custom branding saved it")
	}
	if stored() != 0 || recorded() != 0 {
		t.Errorf("a refused save stored %d rows and recorded %d, want none", stored(), recorded())
	}
	repo.SetPlanGate(&planGate{on: true})
	if err := repo.Save(ctx, Branding{OrganizationID: organization, PrimaryColor: &primary}, actor); err != nil {
		t.Fatal(err)
	}
	if stored() != 1 || recorded() != 1 {
		t.Errorf("a save stored %d rows and recorded %d as the actor's, want 1 each", stored(), recorded())
	}
}
