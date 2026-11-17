//go:build integration

package oidc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestResourceIdentifiersBelongToOneOrganization checks that a resource
// identifier, the audience of the tokens issued for it, can be registered by
// one organization only, and never on a domain another organization verified:
// tokens share one issuer, so a second registration would let one
// organization mint tokens another's service accepts.
func TestResourceIdentifiersBelongToOneOrganization(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	alpha, beta := dbtest.Organization(t), dbtest.Organization(t)
	if _, err := dbtest.Pool(t).Exec(context.Background(), `
		INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at) VALUES ($1, 'Alpha-Bank.example', 'token', NOW())`, alpha); err != nil {
		t.Fatal(err)
	}
	register := func(organization uuid.UUID, identifier string) (int, string) {
		admin := dbtest.User(t, organization, organization)
		h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		return rec.Code, rec.Body.String()
	}
	if code, body := register(beta, "urn:shared-example:api"); code != http.StatusCreated {
		t.Fatalf("register a free identifier: %d %s", code, body)
	}
	if code, body := register(alpha, "urn:shared-example:api"); code != http.StatusConflict || !strings.Contains(body, errs.CodeOIDCResourceExists) {
		t.Errorf("register another organisation's identifier: %d %s, want 409 %s", code, body, errs.CodeOIDCResourceExists)
	}
	for _, identifier := range []string{"https://alpha-bank.example/loans", "https://api.alpha-bank.example"} {
		if code, body := register(beta, identifier); code != http.StatusConflict || !strings.Contains(body, errs.CodeOIDCResourceDomainTaken) {
			t.Errorf("register %s on another organisation's verified domain: %d %s, want 409 %s", identifier, code, body, errs.CodeOIDCResourceDomainTaken)
		}
	}
	if code, body := register(alpha, "https://api.alpha-bank.example"); code != http.StatusCreated {
		t.Errorf("register on your own verified domain: %d %s, want 201", code, body)
	}
	verifyDomain(t, beta, "notalpha-bank.example")
	if code, body := register(beta, "https://notalpha-bank.example"); code != http.StatusCreated {
		t.Errorf("register on a domain that merely ends the same way: %d %s, want 201", code, body)
	}
}

// verifyDomain records domain as verified by organization.
func verifyDomain(t *testing.T, organization uuid.UUID, domain string) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), `
		INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at) VALUES ($1, $2, 'token', NOW())`, organization, domain); err != nil {
		t.Fatal(err)
	}
}

// TestResourceCannotUseThePlatformAudience checks that no organization may
// register the platform's own token audience or issuer, or any identifier on
// the API's public host, even one on a domain it has verified: its tokens
// would carry an audience the platform's own services accept.
func TestResourceCannotUseThePlatformAudience(t *testing.T) {
	key, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokens.NewIssuer(key, "https://issuer.platform-qeet.example", "https://audience.platform-qeet.example/v1", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(dbtest.Pool(t), issuer)
	organization := dbtest.Organization(t)
	verifyDomain(t, organization, "platform-qeet.example")
	h := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization),
		(&Handler{Service: svc, PublicBaseURL: "https://api.platform-qeet.example"}).Mount)
	for _, identifier := range []string{
		"https://audience.platform-qeet.example/v1",
		"https://issuer.platform-qeet.example",
		"https://issuer.platform-qeet.example/orders",
		"https://API.platform-qeet.example/orders",
	} {
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeOIDCResourceReserved) {
			t.Errorf("register %s: %d %s, want 409 %s", identifier, rec.Code, rec.Body.String(), errs.CodeOIDCResourceReserved)
		}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/oidc/resources", map[string]any{"identifier": "https://orders.platform-qeet.example", "name": "API"}); rec.Code != http.StatusCreated {
		t.Errorf("register another host on the organisation's domain: %d %s, want 201", rec.Code, rec.Body.String())
	}
}

// TestResourceHostMustBeVerifiedByTheOrganization checks that a resource on a
// host is registered only by an organization that has verified that host or a
// domain above it, so nobody gets tokens for a host before its owner proves
// it; an identifier without a host, such as a URN, needs no domain.
func TestResourceHostMustBeVerifiedByTheOrganization(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	h := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), (&Handler{Service: svc}).Mount)
	register := func(identifier string) (int, string) {
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		return rec.Code, rec.Body.String()
	}
	if code, body := register("https://api.unproved-host.example"); code != http.StatusForbidden || !strings.Contains(body, errs.CodeOIDCResourceDomainUnverified) {
		t.Errorf("register on a host nobody verified: %d %s, want 403 %s", code, body, errs.CodeOIDCResourceDomainUnverified)
	}
	verifyDomain(t, organization, "unproved-host.example")
	for _, identifier := range []string{"https://api.unproved-host.example", "https://unproved-host.example/v2", "urn:unproved-host:orders"} {
		if code, body := register(identifier); code != http.StatusCreated {
			t.Errorf("register %s once its domain is verified: %d %s, want 201", identifier, code, body)
		}
	}
}
