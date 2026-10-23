//go:build integration

package adminportal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// branded is an organisation's login branding with only a primary colour.
type branded struct{}

func (branded) LoginBranding(context.Context, uuid.UUID) (string, string, string, string) {
	return "", "#123456", "", ""
}

// idpCertificate returns a throwaway PEM certificate for an identity provider.
func idpCertificate(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// portal sends a request to the public portal with the given bearer token or
// session cookie.
func portal(t *testing.T, h http.Handler, method, path, bearer, session string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, "/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: portalSessionCookie, Value: session})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPortalLinkConfiguresOnlyWhatItGrants checks that an administrator's link
// is redeemed once for a short session, which manages the organisation's SAML
// connections and SCIM token as far as the link allows and no further, and
// that revoking the link or signing out ends it at once.
func TestPortalLinkConfiguresOnlyWhatItGrants(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	users := user.NewRepository(pool)
	h := &Handler{
		Service: NewService(pool, branded{}, "https://login.example.test"),
		SAML:    saml.NewService(pool, auth.NewService(pool, users, dbtest.Issuer(t)), "https://id.example.test"),
		SCIM:    scim.NewService(pool, users),
	}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	links := "/tenants/" + tenant.String() + "/admin-portal/links"

	generate := func(capabilities ...string) (uuid.UUID, string) {
		t.Helper()
		rec := dbtest.Do(t, asAdmin, http.MethodPost, links, map[string]any{"capabilities": capabilities, "ttl_seconds": 60})
		var out struct {
			Link  Link   `json:"link"`
			Token string `json:"token"`
			URL   string `json:"url"`
		}
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusCreated || out.URL != "https://login.example.test/admin-portal#token="+out.Token {
			t.Fatalf("generate: %d %s", rec.Code, rec.Body.String())
		}
		if ttl := time.Until(out.Link.ExpiresAt); ttl < 14*time.Minute || ttl > 16*time.Minute {
			t.Errorf("a one-minute link lasts %v, want the 15-minute minimum", ttl)
		}
		return out.Link.ID, out.Token
	}
	redeem := func(token string) string {
		t.Helper()
		rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("redeem: %d %s", rec.Code, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == portalSessionCookie {
				return c.Value
			}
		}
		t.Fatal("redeem set no session cookie")
		return ""
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, links, map[string]any{"capabilities": []string{"billing"}}); rec.Code/100 != 4 {
		t.Errorf("a link for an unknown capability: %d, want refused", rec.Code)
	}

	linkID, token := generate("saml", "SAML")
	session := redeem(token)
	if rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil); rec.Code/100 != 4 {
		t.Errorf("redeeming a link twice: %d, want refused", rec.Code)
	}
	var pc PortalContext
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/context", "", session, nil), &pc)
	if len(pc.Capabilities) != 1 || pc.Capabilities[0] != "saml" || pc.TenantName == "" || pc.Branding == nil || pc.Branding.PrimaryColor != "#123456" {
		t.Errorf("portal context %+v; want the organisation, its branding and SAML only", pc)
	}

	rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{
		"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": idpCertificate(t), "email_attribute": "email",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create SAML connection: %d %s", rec.Code, rec.Body.String())
	}
	var conn saml.Connection
	dbtest.Decode(t, rec, &conn)
	if rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{"name": "Incomplete"}); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSAMLFieldsRequired) {
		t.Errorf("an incomplete connection: %d %s", rec.Code, rec.Body.String())
	}
	connPath := "/admin-portal/saml/" + conn.ID.String()
	if rec := portal(t, public, http.MethodGet, "/admin-portal/saml", "", session, nil); !strings.Contains(rec.Body.String(), conn.ID.String()) {
		t.Errorf("SAML connections: %s", rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, connPath, "", session, nil); rec.Code != http.StatusOK {
		t.Errorf("get the connection: %d", rec.Code)
	}
	var result saml.TestResult
	dbtest.Decode(t, portal(t, public, http.MethodPost, connPath+"/test", "", session, nil), &result)
	if !result.OK {
		t.Errorf("preflight of a complete connection: %+v", result)
	}
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "retired"}); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSAMLStatusInvalid) {
		t.Errorf("an unknown status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "active"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active"`) {
		t.Errorf("activate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("SCIM through a SAML-only link: %d %s", rec.Code, rec.Body.String())
	}

	elsewhere, err := h.SAML.(*saml.Service).List(ctx, other)
	if err != nil || len(elsewhere) != 0 {
		t.Errorf("another organisation's connections %v, %v; want none", elsewhere, err)
	}
	if rec := portal(t, public, http.MethodDelete, connPath, "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete the connection: %d", rec.Code)
	}
	var actions []string
	rows, err := pool.Query(ctx, `SELECT action FROM audit.events WHERE tenant_id = $1 AND actor_type = 'admin_portal' ORDER BY created_at`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if strings.Join(actions, ",") != "saml.connection_created,saml.connection_updated,saml.connection_deleted" {
		t.Errorf("recorded %v; want each change, as the portal", actions)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, links+"/"+linkID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/context", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSessionInvalid) {
		t.Errorf("a session after its link was revoked: %d %s", rec.Code, rec.Body.String())
	}

	_, token = generate("scim")
	session = redeem(token)
	rec = portal(t, public, http.MethodPost, "/admin-portal/scim/token", "", session, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"token_set":true`) {
		t.Fatalf("rotate the SCIM token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); strings.Contains(rec.Body.String(), `"token":`) {
		t.Errorf("the SCIM settings returned the token: %s", rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/scim/token", "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("revoke the SCIM token: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/saml", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("SAML through a SCIM-only link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/session", "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSessionInvalid) {
		t.Errorf("a session after signing out: %d %s", rec.Code, rec.Body.String())
	}

	for name, bearer := range map[string]string{"no token": "", "an unknown token": "forged"} {
		if rec := portal(t, public, http.MethodPost, "/admin-portal/session", bearer, "", nil); rec.Code/100 != 4 {
			t.Errorf("redeem with %s: %d, want refused", name, rec.Code)
		}
	}
	_, token = generate("scim")
	if _, err := pool.Exec(ctx, `UPDATE tenant.admin_portal_links SET expires_at = now() - interval '1 minute' WHERE token_hash = (SELECT token_hash FROM tenant.admin_portal_links WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalLinkExpired) {
		t.Errorf("redeem an expired link: %d %s", rec.Code, rec.Body.String())
	}

	var list struct {
		Items []Link `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, links, nil), &list)
	if len(list.Items) != 3 {
		t.Errorf("%d links listed, want 3", len(list.Items))
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	if rec := dbtest.Do(t, asOther, http.MethodDelete, "/tenants/"+other.String()+"/admin-portal/links/"+list.Items[0].ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation revoking a link: %d, want 404", rec.Code)
	}
}
