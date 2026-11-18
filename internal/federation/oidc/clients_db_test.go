//go:build integration

package oidc

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// poolLimiter caps applications at limit, reading on the pool as the plan
// service does.
type poolLimiter struct {
	pool  *pgxpool.Pool
	limit int
}

func (l poolLimiter) Limit(ctx context.Context, _ uuid.UUID, _ string) (int, error) {
	var one int
	return l.limit, l.pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

// TestClientRegistrationPlanCapWithOneConnection checks, with only one
// connection free, that both registration routes apply the plan's cap on
// applications: under it they register, at it they refuse, before any
// validation of the request.
func TestClientRegistrationPlanCapWithOneConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	svc.SetPlanLimiter(poolLimiter{pool: pool, limit: 2})
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	inOrganization := "/organizations/" + organization.String() + "/oidc/clients"
	app := map[string]any{"name": "App", "redirect_uris": []string{testRedirect}}

	dbtest.LeaveOneConnection(t)
	for _, path := range []string{inOrganization, "/oidc/clients"} {
		if rec := dbtest.Do(t, h, http.MethodPost, path, app); rec.Code != http.StatusCreated {
			t.Errorf("POST %s under the cap = %d %s, want 201", path, rec.Code, rec.Body.String())
		}
	}
	invalid := map[string]any{"name": "App", "type": "neither"}
	for _, path := range []string{inOrganization, "/oidc/clients"} {
		for _, body := range []map[string]any{app, invalid} {
			if rec := dbtest.Do(t, h, http.MethodPost, path, body); rec.Code != http.StatusPaymentRequired {
				t.Errorf("POST %s %v at the cap = %d %s, want 402", path, body, rec.Code, rec.Body.String())
			}
		}
	}
}

// TestOIDCClientsStayInTheirOrganization checks that one organization can neither read nor
// change another organization's OIDC client, and that its users can't authorize it.
func TestOIDCClientsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	clientA, secretA := registerClient(t, svc, organizationA)
	adminB := dbtest.User(t, organizationB, organizationB)

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc}).Mount)
	inB := "/organizations/" + organizationB.String() + "/oidc/clients/" + clientA.ID.String()
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
		{http.MethodGet, "/organizations/" + organizationA.String() + "/oidc/clients", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	var page struct {
		Items []Client `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/oidc/clients", nil), &page)
	if slices.ContainsFunc(page.Items, func(c Client) bool { return c.ID == clientA.ID }) {
		t.Error("organization B's client list includes organization A's client")
	}

	got, err := svc.GetClient(ctx, organizationA, clientA.ID)
	if err != nil || got.Name != "App" {
		t.Fatalf("organization A's client after organization B's calls: %+v, %v", got, err)
	}
	if _, err := svc.authenticateClient(ctx, clientA.ClientID, secretA); err != nil {
		t.Errorf("organization A's client secret stopped working: %v", err)
	}
	_, challenge, _ := codes.URLToken()
	if _, _, err := svc.Authorize(ctx, adminB.ID, clientA.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256"); err == nil {
		t.Error("an organization B user authorized organization A's client")
	}
}
