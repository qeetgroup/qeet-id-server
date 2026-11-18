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

// TestDomainsStayInTheirOrganization checks that one organization can neither read nor
// change another organization's domain, nor verify a domain that organization has already
// verified.
func TestDomainsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminB := dbtest.User(t, organizationB, organizationB)
	name := dbtest.Unique("acme") + ".example.test"
	domainA, err := svc.Add(ctx, organizationA, name, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("add domain in A: %v", err)
	}
	svc.resolver = txtRecords{domainA.VerificationToken}
	if _, err := svc.Verify(ctx, domainA.ID, organizationA, audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("verify domain in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc}).Mount)
	inB := "/organizations/" + organizationB.String() + "/domains"
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPatch, inB + "/" + domainA.ID.String(), map[string]any{"sso_enabled": true, "jit_enabled": true}, http.StatusNotFound},
		{http.MethodPost, inB + "/" + domainA.ID.String() + "/verify", nil, http.StatusNotFound},
		{http.MethodDelete, inB + "/" + domainA.ID.String(), nil, http.StatusNotFound},
		{http.MethodGet, "/organizations/" + organizationA.String() + "/domains", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, inB, nil)); slices.Contains(ids, domainA.ID) {
		t.Error("organization B's domain list includes organization A's")
	}

	// B may add the same name, but can't verify it while A holds it.
	domainB, err := svc.Add(ctx, organizationB, name, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("add the same domain in B: %v", err)
	}
	svc.resolver = txtRecords{domainB.VerificationToken}
	if rec := dbtest.Do(t, asB, http.MethodPost, inB+"/"+domainB.ID.String()+"/verify", nil); rec.Code != http.StatusConflict {
		t.Errorf("organization B verifies organization A's domain: status %d, want 409 (%s)", rec.Code, rec.Body.String())
	}

	if n := dbtest.Count(t, `
		SELECT count(*) FROM organization.domains
		WHERE id = $1 AND verified_at IS NOT NULL AND NOT sso_enabled AND NOT jit_enabled
	`, domainA.ID); n != 1 {
		t.Error("organization B changed organization A's domain")
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
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	dns := &countingResolver{}
	svc := NewService(pool)
	svc.resolver, svc.web = dns, nil
	setHost := func(id uuid.UUID, host string) {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.branding (organization_id, custom_domain) VALUES ($1, $2)
			ON CONFLICT (organization_id) DO UPDATE SET custom_domain = EXCLUDED.custom_domain`, id, host); err != nil {
			t.Fatal(err)
		}
	}
	setHost(organization, "auth.acme.example")
	setHost(other, "auth.other.example")

	first, err := svc.LoginDomain(ctx, organization)
	if err != nil || first.CheckedAt == nil || dns.lookups != 1 {
		t.Fatalf("first read: %+v, %v, %d lookups; want it checked once, with its time", first, err, dns.lookups)
	}
	again, err := svc.LoginDomain(ctx, organization)
	if err != nil || dns.lookups != 1 || again.CheckedAt == nil || !again.CheckedAt.Equal(*first.CheckedAt) || again.Status != first.Status {
		t.Errorf("second read: %+v, %v, %d lookups; want the kept check, not a new one", again, err, dns.lookups)
	}
	dns.records = []string{"qeetid-verify=" + shortOrganization(organization)}
	checked, err := svc.CheckLoginDomain(ctx, organization)
	if err != nil || dns.lookups != 2 || !checked.DNSVerified || !checked.CheckedAt.After(*first.CheckedAt) {
		t.Errorf("a new check: %+v, %v, %d lookups; want it run and newer", checked, err, dns.lookups)
	}
	if read, _ := svc.LoginDomain(ctx, organization); dns.lookups != 2 || !read.DNSVerified {
		t.Errorf("a read after the new check: %+v, %d lookups; want the new check kept", read, dns.lookups)
	}
	setHost(organization, "login.acme.example")
	if read, _ := svc.LoginDomain(ctx, organization); dns.lookups != 3 || read.LoginDomain != "login.acme.example" {
		t.Errorf("after the address changed: %+v, %d lookups; want it checked again", read, dns.lookups)
	}
	if read, _ := svc.LoginDomain(ctx, other); dns.lookups != 4 || read.LoginDomain != "auth.other.example" {
		t.Errorf("another organization's read: %+v, %d lookups; want its own check", read, dns.lookups)
	}
}
