//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testRedirect = "https://app.example.test/callback"

// registerClient registers a confidential client in tenant and returns it with
// its secret.
func registerClient(t *testing.T, svc *Service, tenant uuid.UUID) (*Client, string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	client, secret, err := svc.RegisterClient(ctx, tx, CreateClientInput{
		TenantID: tenant, Name: "App", RedirectURIs: []string{testRedirect},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return client, secret
}

// TestOIDCClientsStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's OIDC client, and that its users can't authorize it.
func TestOIDCClientsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	clientA, secretA := registerClient(t, svc, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
	inB := "/tenants/" + tenantB.String() + "/oidc/clients/" + clientA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodGet, inB, nil, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"name": "Renamed"}, http.StatusNotFound},
		{http.MethodPost, inB + "/rotate-secret", nil, http.StatusNotFound},
		{http.MethodDelete, inB, nil, http.StatusNotFound},
		{http.MethodDelete, "/oidc/clients/" + clientA.ID.String(), nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/oidc/clients", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	var page struct {
		Items []Client `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/oidc/clients", nil), &page)
	if slices.ContainsFunc(page.Items, func(c Client) bool { return c.ID == clientA.ID }) {
		t.Error("tenant B's client list includes tenant A's client")
	}

	got, err := svc.GetClient(ctx, tenantA, clientA.ID)
	if err != nil || got.Name != "App" {
		t.Fatalf("tenant A's client after tenant B's calls: %+v, %v", got, err)
	}
	if _, err := svc.authenticateClient(ctx, clientA.ClientID, secretA); err != nil {
		t.Errorf("tenant A's client secret stopped working: %v", err)
	}
	_, challenge, _ := codes.URLToken()
	if _, _, err := svc.Authorize(ctx, adminB.ID, clientA.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256"); err == nil {
		t.Error("a tenant B user authorized tenant A's client")
	}
}

// TestOIDCAuthorizationCodeWithPKCE checks the authorization code grant: the
// code redeems only with its PKCE verifier, once, for tokens naming the user.
func TestOIDCAuthorizationCodeWithPKCE(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(dbtest.Pool(t), issuer)
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)

	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	code, gotTenant, err := svc.Authorize(ctx, user.ID, client.ClientID, testRedirect, []string{"openid"}, "n-0S6_WzA2Mj", challenge, "S256")
	if err != nil || gotTenant != tenant {
		t.Fatalf("authorize: tenant %s, %v", gotTenant, err)
	}

	wrongVerifier := strings.Repeat("a", 43)
	for name, v := range map[string]string{"missing": "", "wrong": wrongVerifier} {
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, v, ""); err == nil {
			t.Errorf("exchange with %s verifier succeeded", name)
		}
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, "wrong-secret", code, testRedirect, verifier, ""); err == nil {
		t.Error("exchange with a wrong client secret succeeded")
	}

	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.IDToken == "" || issued.RefreshToken == "" {
		t.Errorf("exchange returned id token %t, refresh token %t; want both", issued.IDToken != "", issued.RefreshToken != "")
	}
	claims, err := issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if err != nil || claims.UserID != user.ID || claims.TenantID != tenant {
		t.Fatalf("access token claims %+v, %v; want user %s in tenant %s", claims, err, user.ID, tenant)
	}

	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeUsed) {
		t.Errorf("second exchange: %v, want %v", err, errs.ErrOIDCAuthCodeUsed)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("refresh token survived the code's replay")
	}
}
