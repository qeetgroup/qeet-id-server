//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestAdminPortalLinkGenerateAndRedeem drives the whole self-serve Admin
// Portal end to end: a tenant admin generates a capability-scoped link, and an
// external IT admin exchanges it once for a short-lived cookie before using
// token-free routes — proving the capability gate actually blocks the
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	exchange := func(raw string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/admin-portal/session", nil)
		if err != nil {
			t.Fatalf("create exchange request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+raw)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("exchange portal link: %v", err)
		}
		return resp
	}

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
	shareURL, err := url.Parse(portalSvc.URL(samlToken))
	if err != nil {
		t.Fatalf("parse share URL: %v", err)
	}
	if strings.Contains(shareURL.Path, samlToken) || !strings.Contains(shareURL.Fragment, samlToken) {
		t.Fatalf("share URL must carry its one-time token only in the fragment: %s", shareURL)
	}
	exchangeResp := exchange(samlToken)
	if exchangeResp.StatusCode != http.StatusCreated {
		t.Fatalf("exchange status = %d, want 201", exchangeResp.StatusCode)
	}
	portalCookies := exchangeResp.Cookies()
	if len(portalCookies) != 1 || !portalCookies[0].HttpOnly || portalCookies[0].Path != "/v1/admin-portal" || portalCookies[0].SameSite != http.SameSiteStrictMode || portalCookies[0].MaxAge <= 0 || portalCookies[0].MaxAge > 30*60 {
		t.Fatalf("portal session cookie is not narrowly scoped: %+v", portalCookies)
	}
	if exchangeResp.Header.Get("Referrer-Policy") != "no-referrer" || exchangeResp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("portal exchange missing anti-leak headers: %v", exchangeResp.Header)
	}
	exchangeResp.Body.Close()
	replayedExchange := exchange(samlToken)
	replayedExchange.Body.Close()
	if replayedExchange.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second link exchange status = %d, want 401", replayedExchange.StatusCode)
	}

	// context: authenticated by the portal cookie, with no token in the path.
	ctxResp, err := client.Get(srv.URL + "/v1/admin-portal/context")
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
	createResp, err := client.Post(srv.URL+"/v1/admin-portal/saml", "application/json", bytes.NewReader(createBody))
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
	scimResp, err := client.Post(srv.URL+"/v1/admin-portal/scim/token", "application/json", nil)
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
	exchangeResp = exchange(scimToken)
	exchangeResp.Body.Close()
	if exchangeResp.StatusCode != http.StatusCreated {
		t.Fatalf("SCIM link exchange status = %d, want 201", exchangeResp.StatusCode)
	}

	rotateResp, err := client.Post(srv.URL+"/v1/admin-portal/scim/token", "application/json", nil)
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

	samlOnScim, err := client.Get(srv.URL + "/v1/admin-portal/saml")
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
	revokedResp, err := client.Get(srv.URL + "/v1/admin-portal/context")
	if err != nil {
		t.Fatalf("get context (revoked): %v", err)
	}
	revokedResp.Body.Close()
	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("context after revoke status = %d, want 401", revokedResp.StatusCode)
	}

	// an invalid token is rejected, not panicked on
	badResp := exchange("not-a-real-token")
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exchange with invalid token status = %d, want 401", badResp.StatusCode)
	}

	tx4, _ := testPool.Begin(ctx)
	_, logoutToken, err := portalSvc.Generate(ctx, tx4, tenantID, sponsor, []string{"saml"}, time.Hour)
	if err != nil {
		t.Fatalf("generate logout link: %v", err)
	}
	if err := tx4.Commit(ctx); err != nil {
		t.Fatalf("commit logout link: %v", err)
	}
	logoutExchange := exchange(logoutToken)
	logoutExchange.Body.Close()
	logoutReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/admin-portal/session", nil)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout portal session: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("portal logout status = %d, want 204", logoutResp.StatusCode)
	}
	afterLogout, err := client.Get(srv.URL + "/v1/admin-portal/context")
	if err != nil {
		t.Fatalf("context after logout: %v", err)
	}
	afterLogout.Body.Close()
	if afterLogout.StatusCode != http.StatusUnauthorized {
		t.Fatalf("context after logout status = %d, want 401", afterLogout.StatusCode)
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

	if _, _, _, err := portalSvc.Exchange(ctx, raw); err == nil {
		t.Fatal("exchange of an expired link succeeded, want error")
	} else if e := errs.As(err); e == nil || e.Code != errs.ErrAdminPortalLinkExpired.Code {
		t.Errorf("resolve error = %v, want link expired", err)
	}

	tx2, _ := testPool.Begin(ctx)
	link2, raw2, err := portalSvc.Generate(ctx, tx2, tenantID, sponsor, []string{"saml"}, time.Hour)
	if err != nil {
		t.Fatalf("generate session-expiry link: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit session-expiry link: %v", err)
	}
	_, rawSession, _, err := portalSvc.Exchange(ctx, raw2)
	if err != nil {
		t.Fatalf("exchange session-expiry link: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.admin_portal_sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE link_id = $1`, link2.ID); err != nil {
		t.Fatalf("force-expire portal session: %v", err)
	}
	if _, err := portalSvc.ResolveSession(ctx, rawSession); !errors.Is(err, errs.ErrAdminPortalSessionInvalid) {
		t.Fatalf("expired portal session error = %v", err)
	}
}

func TestAdminPortalCookieMutationRequiresCSRF(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("portal-csrf"))
	sponsor := createUserInTenant(t, ctx, tenantID)
	authService, userRepo := newAuth()
	service := adminportal.NewService(testPool, branding.NewRepository(testPool), "https://login.example")
	handler := &adminportal.Handler{
		Service: service,
		SAML:    saml.NewService(testPool, authService, "https://app.example"),
		SCIM:    scim.NewService(testPool, userRepo),
	}
	router := chi.NewRouter()
	router.Use(httpx.CSRF(httpx.CSRFConfig{AllowedOrigins: []string{"https://portal.example"}}))
	router.Route("/v1", func(r chi.Router) { handler.MountPublic(r) })
	server := httptest.NewServer(router)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	tx, _ := testPool.Begin(ctx)
	_, raw, err := service.Generate(ctx, tx, tenantID, sponsor, []string{"scim"}, time.Hour)
	if err != nil {
		t.Fatalf("generate CSRF portal link: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit CSRF portal link: %v", err)
	}
	exchangeReq, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin-portal/session", nil)
	exchangeReq.Header.Set("Authorization", "Bearer "+raw)
	exchangeResp, err := client.Do(exchangeReq)
	if err != nil {
		t.Fatalf("bearer exchange through CSRF middleware: %v", err)
	}
	exchangeResp.Body.Close()
	if exchangeResp.StatusCode != http.StatusCreated {
		t.Fatalf("bearer exchange status = %d, want 201", exchangeResp.StatusCode)
	}
	contextResp, err := client.Get(server.URL + "/v1/admin-portal/context")
	if err != nil {
		t.Fatalf("portal context: %v", err)
	}
	contextResp.Body.Close()

	blocked, err := client.Post(server.URL+"/v1/admin-portal/scim/token", "application/json", nil)
	if err != nil {
		t.Fatalf("CSRF-blocked request: %v", err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mutation without CSRF status = %d, want 403", blocked.StatusCode)
	}
	serverURL, _ := url.Parse(server.URL)
	var csrfToken string
	for _, cookie := range jar.Cookies(serverURL) {
		if cookie.Name == "qe_csrf" {
			csrfToken = cookie.Value
		}
	}
	if csrfToken == "" {
		t.Fatal("portal context did not issue a CSRF cookie")
	}
	allowedReq, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin-portal/scim/token", nil)
	allowedReq.Header.Set("Origin", "https://portal.example")
	allowedReq.Header.Set("X-CSRF-Token", csrfToken)
	allowedResp, err := client.Do(allowedReq)
	if err != nil {
		t.Fatalf("CSRF-authorized request: %v", err)
	}
	allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("cookie mutation with CSRF status = %d, want 200", allowedResp.StatusCode)
	}
}
