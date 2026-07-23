//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAdminPortalLinkGenerateAndRedeem drives the whole self-serve Admin
// Portal end to end: a tenant admin generates a capability-scoped link
// (service layer — the same call the authed HTTP handler makes), and an
// external IT admin's browser redeems it against the *public*, token-gated
// HTTP surface — proving the capability gate actually blocks the
// non-granted surface, that a granted capability really reaches the live
// saml.Service/scim.Service, and that revocation takes effect immediately.
func TestAdminPortalLinkGenerateAndRedeem(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("portal"))
	sponsor := createUserInTenant(t, ctx, tenantID)

	authSvc, userRepo := newAuth()
	samlSvc := saml.NewService(testPool, authSvc, "https://app.example")
	scimSvc := scim.NewService(testPool, userRepo)
	brandingRepo := branding.NewRepository(testPool)
	portalSvc := adminportal.NewService(testPool, brandingRepo, "https://login.example")

	h := &adminportal.Handler{Service: portalSvc, SAML: samlSvc, SCIM: scimSvc}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) { h.MountPublic(r) })
	srv := httptest.NewServer(r)
	defer srv.Close()

	// A SAML-only link.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	samlLink, samlToken, err := portalSvc.Generate(ctx, tx, tenantID, sponsor, []string{"saml"}, time.Hour)
	if err != nil {
		t.Fatalf("generate saml link: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !samlLink.Has("saml") || samlLink.Has("scim") {
		t.Fatalf("saml link capabilities = %v, want exactly [saml]", samlLink.Capabilities)
	}

	// context: public, no capability required
	ctxResp, err := http.Get(srv.URL + "/v1/admin-portal/" + samlToken + "/context")
	if err != nil {
		t.Fatalf("get context: %v", err)
	}
	var pc struct {
		TenantName   string   `json:"tenant_name"`
		Capabilities []string `json:"capabilities"`
	}
	_ = json.NewDecoder(ctxResp.Body).Decode(&pc)
	ctxResp.Body.Close()
	if ctxResp.StatusCode != http.StatusOK {
		t.Fatalf("context status = %d, want 200", ctxResp.StatusCode)
	}
	if len(pc.Capabilities) != 1 || pc.Capabilities[0] != "saml" {
		t.Errorf("context capabilities = %v, want [saml]", pc.Capabilities)
	}

	// SAML capability: granted, so create + list must work through the
	// real saml.Service, not a stub
	_, certPEM, err := saml.GenerateIdPKeyPEM("Acme Corp IdP")
	if err != nil {
		t.Fatalf("generate test idp cert: %v", err)
	}
	createBody, err := json.Marshal(map[string]string{
		"name":            "acme-idp",
		"idp_entity_id":   "https://idp.acme.example/metadata",
		"idp_sso_url":     "https://idp.acme.example/sso",
		"idp_certificate": certPEM,
		"email_attribute": "email",
	})
	if err != nil {
		t.Fatalf("marshal create body: %v", err)
	}
	createResp, err := http.Post(srv.URL+"/v1/admin-portal/"+samlToken+"/saml", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("post saml create: %v", err)
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("post saml create status = %d, want 201", createResp.StatusCode)
	}
	// Confirm it actually landed in saml.Service, not a portal-side stub.
	conns, err := samlSvc.List(ctx, tenantID)
	if err != nil {
		t.Fatalf("saml list: %v", err)
	}
	if len(conns) != 1 || conns[0].Name != "acme-idp" {
		t.Fatalf("saml.Service.List = %+v, want one connection named acme-idp", conns)
	}

	// SCIM capability: NOT granted on this link, must 403
	scimResp, err := http.Post(srv.URL+"/v1/admin-portal/"+samlToken+"/scim/token", "application/json", nil)
	if err != nil {
		t.Fatalf("post scim rotate: %v", err)
	}
	scimResp.Body.Close()
	if scimResp.StatusCode != http.StatusForbidden {
		t.Fatalf("scim rotate on saml-only link status = %d, want 403", scimResp.StatusCode)
	}

	// A SCIM-only link, to prove the gate cuts both ways.
	tx2, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	scimLink, scimToken, err := portalSvc.Generate(ctx, tx2, tenantID, sponsor, []string{"scim"}, time.Hour)
	if err != nil {
		t.Fatalf("generate scim link: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rotateResp, err := http.Post(srv.URL+"/v1/admin-portal/"+scimToken+"/scim/token", "application/json", nil)
	if err != nil {
		t.Fatalf("post scim rotate (scim link): %v", err)
	}
	var rotated struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(rotateResp.Body).Decode(&rotated)
	rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("scim rotate status = %d, want 200", rotateResp.StatusCode)
	}
	if rotated.Token == "" {
		t.Fatal("scim rotate returned no token")
	}
	// Confirm it actually landed in scim.Service, not a stub.
	cfg, err := scimSvc.Config(ctx, tenantID)
	if err != nil {
		t.Fatalf("scim config: %v", err)
	}
	if !cfg.TokenSet {
		t.Error("scim config token_set = false after portal rotate, want true")
	}

	samlOnScim, err := http.Get(srv.URL + "/v1/admin-portal/" + scimToken + "/saml")
	if err != nil {
		t.Fatalf("get saml (scim link): %v", err)
	}
	samlOnScim.Body.Close()
	if samlOnScim.StatusCode != http.StatusForbidden {
		t.Fatalf("saml list on scim-only link status = %d, want 403", samlOnScim.StatusCode)
	}

	// revocation takes effect immediately
	tx3, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := portalSvc.Revoke(ctx, tx3, tenantID, scimLink.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := tx3.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	revokedResp, err := http.Get(srv.URL + "/v1/admin-portal/" + scimToken + "/context")
	if err != nil {
		t.Fatalf("get context (revoked): %v", err)
	}
	revokedResp.Body.Close()
	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("context after revoke status = %d, want 401", revokedResp.StatusCode)
	}

	// an invalid token is rejected, not panicked on
	badResp, err := http.Get(srv.URL + "/v1/admin-portal/not-a-real-token/context")
	if err != nil {
		t.Fatalf("get context (bad token): %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("context with invalid token status = %d, want 401", badResp.StatusCode)
	}
}

// TestAdminPortalLinkExpiry proves Resolve rejects a link once its TTL has
// elapsed, without requiring the test to actually sleep out an hour.
func TestAdminPortalLinkExpiry(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("portalexp"))
	sponsor := createUserInTenant(t, ctx, tenantID)
	brandingRepo := branding.NewRepository(testPool)
	portalSvc := adminportal.NewService(testPool, brandingRepo, "https://login.example")

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	link, raw, err := portalSvc.Generate(ctx, tx, tenantID, sponsor, []string{"saml"}, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if _, err := testPool.Exec(ctx, `UPDATE tenant.admin_portal_links SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, link.ID); err != nil {
		t.Fatalf("force-expire: %v", err)
	}

	if _, err := portalSvc.Resolve(ctx, raw); err == nil {
		t.Fatal("resolve of an expired link succeeded, want error")
	} else if e := errs.As(err); e == nil || e.Code != "unauthorized" {
		t.Errorf("resolve error = %v, want unauthorized", err)
	}
}
