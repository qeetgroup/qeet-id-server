//go:build integration

package oidc

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestResourceIdentifiersBelongToOneOrganisation checks that a resource
// identifier, the audience of the tokens issued for it, can be registered by
// one organisation only, and never on a domain another organisation verified:
// tokens share one issuer, so a second registration would let one
// organisation mint tokens another's service accepts.
func TestResourceIdentifiersBelongToOneOrganisation(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	alpha, beta := dbtest.Tenant(t), dbtest.Tenant(t)
	if _, err := dbtest.Pool(t).Exec(context.Background(), `
		INSERT INTO tenant.domains (tenant_id, domain, verification_token, verified_at) VALUES ($1, 'Alpha-Bank.example', 'token', NOW())`, alpha); err != nil {
		t.Fatal(err)
	}
	register := func(tenant uuid.UUID, identifier string) (int, string) {
		admin := dbtest.User(t, tenant, tenant)
		h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/oidc/resources", map[string]any{"identifier": identifier, "name": "API"})
		return rec.Code, rec.Body.String()
	}
	if code, body := register(beta, "https://api.shared.example"); code != http.StatusCreated {
		t.Fatalf("register a free identifier: %d %s", code, body)
	}
	if code, body := register(alpha, "https://api.shared.example"); code != http.StatusConflict || !strings.Contains(body, errs.CodeOIDCResourceExists) {
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
	if code, body := register(beta, "https://notalpha-bank.example"); code != http.StatusCreated {
		t.Errorf("register on a domain that merely ends the same way: %d %s, want 201", code, body)
	}
}
