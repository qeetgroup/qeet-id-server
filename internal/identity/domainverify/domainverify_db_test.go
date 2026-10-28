//go:build integration

package domainverify

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

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

// countingResolver answers every TXT lookup with records and counts them.
type countingResolver struct {
	records []string
	lookups int
}

func (r *countingResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.lookups++
	return r.records, nil
}

// TestLoginDomainKeepsItsLastCheck checks that reading the sign-in address
// returns the last check instead of checking again, that a new check is run on
// request or when the address changes, and that each says when it was made.
func TestLoginDomainKeepsItsLastCheck(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	dns := &countingResolver{}
	svc := NewService(pool)
	svc.resolver, svc.web = dns, nil
	setHost := func(id uuid.UUID, host string) {
		if _, err := pool.Exec(ctx, `INSERT INTO tenant.branding (tenant_id, custom_domain) VALUES ($1, $2)
			ON CONFLICT (tenant_id) DO UPDATE SET custom_domain = EXCLUDED.custom_domain`, id, host); err != nil {
			t.Fatal(err)
		}
	}
	setHost(tenant, "auth.acme.example")
	setHost(other, "auth.other.example")

	first, err := svc.LoginDomain(ctx, tenant)
	if err != nil || first.CheckedAt == nil || dns.lookups != 1 {
		t.Fatalf("first read: %+v, %v, %d lookups; want it checked once, with its time", first, err, dns.lookups)
	}
	again, err := svc.LoginDomain(ctx, tenant)
	if err != nil || dns.lookups != 1 || again.CheckedAt == nil || !again.CheckedAt.Equal(*first.CheckedAt) || again.Status != first.Status {
		t.Errorf("second read: %+v, %v, %d lookups; want the kept check, not a new one", again, err, dns.lookups)
	}
	dns.records = []string{"qeetid-verify=" + shortTenant(tenant)}
	checked, err := svc.CheckLoginDomain(ctx, tenant)
	if err != nil || dns.lookups != 2 || !checked.DNSVerified || !checked.CheckedAt.After(*first.CheckedAt) {
		t.Errorf("a new check: %+v, %v, %d lookups; want it run and newer", checked, err, dns.lookups)
	}
	if read, _ := svc.LoginDomain(ctx, tenant); dns.lookups != 2 || !read.DNSVerified {
		t.Errorf("a read after the new check: %+v, %d lookups; want the new check kept", read, dns.lookups)
	}
	setHost(tenant, "login.acme.example")
	if read, _ := svc.LoginDomain(ctx, tenant); dns.lookups != 3 || read.LoginDomain != "login.acme.example" {
		t.Errorf("after the address changed: %+v, %d lookups; want it checked again", read, dns.lookups)
	}
	if read, _ := svc.LoginDomain(ctx, other); dns.lookups != 4 || read.LoginDomain != "auth.other.example" {
		t.Errorf("another organisation's read: %+v, %d lookups; want its own check", read, dns.lookups)
	}
}
