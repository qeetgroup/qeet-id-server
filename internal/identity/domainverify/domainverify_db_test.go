//go:build integration

package domainverify

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// txtRecords answers every TXT lookup with its records.
type txtRecords []string

func (r txtRecords) LookupTXT(context.Context, string) ([]string, error) { return r, nil }

// TestDomainsStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's domain, nor verify a domain that tenant has already
// verified.
func TestDomainsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)
	name := dbtest.Unique("acme") + ".example.test"
	domainA, err := svc.Add(ctx, tenantA, name, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("add domain in A: %v", err)
	}
	svc.resolver = txtRecords{domainA.VerificationToken}
	if _, err := svc.Verify(ctx, domainA.ID, tenantA, audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("verify domain in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
	inB := "/tenants/" + tenantB.String() + "/domains"
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPatch, inB + "/" + domainA.ID.String(), map[string]any{"sso_enabled": true, "is_default": true}, http.StatusNotFound},
		{http.MethodPost, inB + "/" + domainA.ID.String() + "/verify", nil, http.StatusNotFound},
		{http.MethodDelete, inB + "/" + domainA.ID.String(), nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/domains", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB, nil)); slices.Contains(ids, domainA.ID) {
		t.Error("tenant B's domain list includes tenant A's")
	}

	// B may add the same name, but can't verify it while A holds it.
	domainB, err := svc.Add(ctx, tenantB, name, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("add the same domain in B: %v", err)
	}
	svc.resolver = txtRecords{domainB.VerificationToken}
	if rec := dbtest.Do(t, asB, http.MethodPost, inB+"/"+domainB.ID.String()+"/verify", nil); rec.Code != http.StatusConflict {
		t.Errorf("tenant B verifies tenant A's domain: status %d, want 409 (%s)", rec.Code, rec.Body.String())
	}

	if n := dbtest.Count(t, `
		SELECT count(*) FROM tenant.domains
		WHERE id = $1 AND verified_at IS NOT NULL AND NOT sso_enabled AND NOT is_default
	`, domainA.ID); n != 1 {
		t.Error("tenant B changed tenant A's domain")
	}
}
