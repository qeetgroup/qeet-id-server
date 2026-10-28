//go:build integration

package secret

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestSecretsStayInTheirTenant checks that one tenant can neither reveal nor
// change another tenant's secret, and that a vault read by name finds only its
// own secret of that name.
func TestSecretsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, err := NewService(ctx, dbtest.Pool(t), StaticKeyProvider{Key: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)
	secretA, err := svc.Create(ctx, tenantA, "stripe", "", "sk_live_tenant_a")
	if err != nil {
		t.Fatalf("create secret in A: %v", err)
	}

	principal := dbtest.Principal(adminB.ID, tenantB)
	principal.Scopes = []string{"vault:read"}
	asB := dbtest.Serve(principal, (&Handler{Service: svc}).Mount)
	inB := "/tenants/" + tenantB.String() + "/secrets/" + secretA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, inB + "/reveal", nil, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"value": "sk_live_tenant_b"}, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"scope": "agents"}, http.StatusNotFound},
		{http.MethodDelete, inB, nil, http.StatusNotFound},
		{http.MethodGet, "/vault/stripe", nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/secrets", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/secrets", nil)); slices.Contains(ids, secretA.ID) {
		t.Error("tenant B's secret list includes tenant A's")
	}

	if _, err := svc.Create(ctx, tenantB, "stripe", "", "sk_live_tenant_b"); err != nil {
		t.Fatalf("create secret in B: %v", err)
	}
	var vault struct {
		Value string `json:"value"`
	}
	dbtest.Decode(t, dbtest.Do(t, asB, http.MethodGet, "/vault/stripe", nil), &vault)
	if vault.Value != "sk_live_tenant_b" {
		t.Errorf("tenant B's vault read returned %q, want its own secret", vault.Value)
	}
	if _, value, err := svc.Reveal(ctx, tenantA, secretA.ID); err != nil || value != "sk_live_tenant_a" {
		t.Errorf("tenant A's secret after tenant B's calls: %q, %v", value, err)
	}
}

// TestSecretListIsCapped checks that a tenant with more secrets than one list
// answers holds gets the first paging.MaxListItems of them, marked truncated.
func TestSecretListIsCapped(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, err := NewService(ctx, dbtest.Pool(t), StaticKeyProvider{Key: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO tenant.secrets (tenant_id, name, ciphertext, nonce)
		SELECT $1, 'secret-' || n, '\x00', '\x00' FROM generate_series(1, $2::int) AS n
	`, tenant, paging.MaxListItems+1); err != nil {
		t.Fatal(err)
	}
	principal := dbtest.Principal(admin.ID, tenant)
	principal.Scopes = []string{"vault:read"}
	rec := dbtest.Do(t, dbtest.Serve(principal, (&Handler{Service: svc}).Mount), http.MethodGet, "/tenants/"+tenant.String()+"/secrets", nil)
	var body struct {
		Items     []json.RawMessage `json:"items"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list: %d %v", rec.Code, err)
	}
	if len(body.Items) != paging.MaxListItems || !body.Truncated {
		t.Errorf("list of %d secrets: %d items, truncated %v; want %d, true", paging.MaxListItems+1, len(body.Items), body.Truncated, paging.MaxListItems)
	}
}

