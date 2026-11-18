//go:build integration

package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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
		rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		return rec.Code, rec.Body.String()
	}
	if code, body := register(beta, "urn:shared-example:api"); code != http.StatusCreated {
		t.Fatalf("register a free identifier: %d %s", code, body)
	}
	if code, body := register(alpha, "urn:shared-example:api"); code != http.StatusConflict || !strings.Contains(body, CodeResourceExists) {
		t.Errorf("register another organization's identifier: %d %s, want 409 %s", code, body, CodeResourceExists)
	}
	for _, identifier := range []string{"https://alpha-bank.example/loans", "https://api.alpha-bank.example"} {
		if code, body := register(beta, identifier); code != http.StatusConflict || !strings.Contains(body, CodeResourceDomainTaken) {
			t.Errorf("register %s on another organization's verified domain: %d %s, want 409 %s", identifier, code, body, CodeResourceDomainTaken)
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
		rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), CodeResourceReserved) {
			t.Errorf("register %s: %d %s, want 409 %s", identifier, rec.Code, rec.Body.String(), CodeResourceReserved)
		}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/oidc/resources", map[string]any{"identifier": "https://orders.platform-qeet.example", "name": "API"}); rec.Code != http.StatusCreated {
		t.Errorf("register another host on the organization's domain: %d %s, want 201", rec.Code, rec.Body.String())
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
		rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		return rec.Code, rec.Body.String()
	}
	if code, body := register("https://api.unproved-host.example"); code != http.StatusForbidden || !strings.Contains(body, CodeResourceDomainUnverified) {
		t.Errorf("register on a host nobody verified: %d %s, want 403 %s", code, body, CodeResourceDomainUnverified)
	}
	verifyDomain(t, organization, "unproved-host.example")
	for _, identifier := range []string{"https://api.unproved-host.example", "https://unproved-host.example/v2", "urn:unproved-host:orders"} {
		if code, body := register(identifier); code != http.StatusCreated {
			t.Errorf("register %s once its domain is verified: %d %s, want 201", identifier, code, body)
		}
	}
}

// TestResourcesAndShadowAIReview checks that an organization registers each
// resource once, served only by one of its own applications, which may then
// introspect tokens for it where another may not, and that an unreviewed
// machine application is listed until an admin reviews it.
func TestResourcesAndShadowAIReview(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	client, secret := registerClient(t, svc, organization)
	server, serverSecret := registerClient(t, svc, organization)
	bystander, bystanderSecret := registerClient(t, svc, organization)
	foreign, _ := registerClient(t, svc, otherOrganization)
	resources := "/organizations/" + organization.String() + "/oidc/resources"
	verifyDomain(t, organization, strings.TrimPrefix(resourceA, "https://"))

	for _, tc := range []struct {
		name string
		body map[string]any
		code string
	}{
		{"served by another organization's application", map[string]any{"identifier": resourceA, "server_client_id": foreign.ClientID}, CodeClientNotFound},
		{"a relative identifier", map[string]any{"identifier": "api/orders"}, CodeResourceInvalid},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, tc.body); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("register a resource %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.code)
		}
	}
	var res Resource
	rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, map[string]any{"identifier": resourceA, "name": "Orders", "server_client_id": server.ClientID})
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusCreated || res.ServerClientID != server.ClientID {
		t.Fatalf("register a resource: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, map[string]any{"identifier": resourceA}); !strings.Contains(rec.Body.String(), CodeResourceExists) {
		t.Errorf("register it again: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, resources, nil)); !slices.Equal(ids, []uuid.UUID{res.ID}) {
		t.Errorf("resources %v, want only %s", ids, res.ID)
	}

	issued := redeemCode(t, svc, client, secret, admin.ID, resourceA)
	if out, err := svc.Introspect(ctx, server.ClientID, serverSecret, issued.AccessToken, ""); err != nil || out["active"] != true || out["resource"] != resourceA {
		t.Errorf("the resource's server introspecting its token: %v, %v; want it active, for the resource", out, err)
	}
	if out, err := svc.Introspect(ctx, bystander.ClientID, bystanderSecret, issued.AccessToken, ""); err != nil || out["active"] != false {
		t.Errorf("an application serving no resource introspecting the token: %v, %v; want inactive", out, err)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, resources+"/"+res.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove the resource: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, resources+"/"+res.ID.String(), nil); !strings.Contains(rec.Body.String(), CodeResourceNotFound) {
		t.Errorf("remove it again: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("a grant for a removed resource renewed")
	}

	if _, _, err := svc.RegisterClient(ctx, nil, CreateClientInput{OrganizationID: organization, Name: "Cron", GrantTypes: []string{"client_credentials"}}); !errors.Is(err, ErrGrantTypeUnsupported) {
		t.Errorf("register a client_credentials application: %v, want %v (machine callers are service principals)", err, ErrGrantTypeUnsupported)
	}
	machine, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Name: "Agent", GrantTypes: []string{"token_exchange"}})
	shadow := "/organizations/" + organization.String() + "/oidc/clients/shadow-ai"
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, shadow, nil)); !slices.Equal(ids, []uuid.UUID{machine.ID}) {
		t.Errorf("shadow-AI candidates %v, want only the machine application %s", ids, machine.ID)
	}
	review := "/organizations/" + organization.String() + "/oidc/clients/"
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, review+foreign.ID.String()+"/review", nil); rec.Code != http.StatusNotFound {
		t.Errorf("review another organization's application: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, review+machine.ID.String()+"/review", nil); rec.Code != http.StatusNoContent {
		t.Errorf("review: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, shadow, nil)); len(ids) != 0 {
		t.Errorf("shadow-AI candidates after review %v, want none", ids)
	}
}
