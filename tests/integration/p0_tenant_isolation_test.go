//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
)

func TestCreateUserUsesPrincipalTenant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("user-scope-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("user-scope-b"))
	actorID := createUserInTenant(t, ctx, tenantA)

	h := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(validator.WithRequiredStructEnabled())}
	r := chi.NewRouter()
	r.Use(withPrincipal(actorID, tenantA))
	h.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for _, tc := range []struct {
		name     string
		tenantID *uuid.UUID
	}{
		{name: "mismatched tenant is overridden", tenantID: &tenantB},
		{name: "omitted tenant uses principal", tenantID: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"email":        uniqueSlug("created") + "@example.com",
				"display_name": "Created User",
			}
			if tc.tenantID != nil {
				body["tenant_id"] = tc.tenantID.String()
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			resp, err := http.Post(srv.URL+"/users", "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, want 201", resp.StatusCode)
			}
			var created user.User
			if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if created.TenantID != tenantA {
				t.Fatalf("created tenant = %s, want principal tenant %s", created.TenantID, tenantA)
			}
		})
	}
}

func TestLegacyOIDCClientRegistrationUsesPrincipalTenant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("client-scope-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("client-scope-b"))
	actorID := createUserInTenant(t, ctx, tenantA)

	h := &oidc.Handler{Service: oidc.NewService(testPool, mustIssuer())}
	r := chi.NewRouter()
	r.Use(withPrincipal(actorID, tenantA))
	h.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for _, tc := range []struct {
		name     string
		tenantID *uuid.UUID
	}{
		{name: "mismatched tenant is overridden", tenantID: &tenantB},
		{name: "omitted tenant uses principal", tenantID: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"name":          "Integration Client",
				"type":          "confidential",
				"redirect_uris": []string{"https://client.example/callback"},
				"grant_types":   []string{"authorization_code", "refresh_token"},
				"scopes":        []string{"openid", "profile"},
			}
			if tc.tenantID != nil {
				body["tenant_id"] = tc.tenantID.String()
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			resp, err := http.Post(srv.URL+"/oidc/clients", "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("register client: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, want 201", resp.StatusCode)
			}
			var out struct {
				Client oidc.Client `json:"client"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if out.Client.TenantID != tenantA {
				t.Fatalf("client tenant = %s, want principal tenant %s", out.Client.TenantID, tenantA)
			}
		})
	}
}

func TestOIDCAuthorizeRequiresActiveTenantMembership(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("authorize-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("authorize-b"))
	userA := createUserInTenant(t, ctx, tenantA)
	userB := createUserInTenant(t, ctx, tenantB)
	addTenantMembership(t, ctx, userA, tenantA)
	addTenantMembership(t, ctx, userB, tenantB)

	var tenantlessUser uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email)
		VALUES (NULL, $1) RETURNING id
	`, uniqueSlug("tenantless")+"@example.com").Scan(&tenantlessUser); err != nil {
		t.Fatalf("create tenant-less user: %v", err)
	}

	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantB, "https://client.example/callback")
	authorize := func(userID uuid.UUID) error {
		_, _, err := svc.Authorize(ctx, userID, client.ClientID, "https://client.example/callback", []string{"openid"}, "", "", "")
		return err
	}

	if err := authorize(userA); err == nil {
		t.Fatal("user from another tenant authorized the client")
	}
	if err := authorize(tenantlessUser); err == nil {
		t.Fatal("tenant-less user authorized a tenant client")
	}
	if err := authorize(userB); err != nil {
		t.Fatalf("active tenant member rejected: %v", err)
	}

	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, userB); err != nil {
		t.Fatalf("suspend member: %v", err)
	}
	if err := authorize(userB); err == nil {
		t.Fatal("suspended member authorized the client")
	}
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'active' WHERE id = $1`, userB); err != nil {
		t.Fatalf("reactivate member: %v", err)
	}
	if err := svc.GrantConsent(ctx, userB, client.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, userB, tenantB); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	if err := authorize(userB); err == nil {
		t.Fatal("existing consent bypassed revoked membership")
	}
}

func TestGDPRPurgeEnforcesTenantOwnership(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("purge-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("purge-b"))
	victimID := createUserInTenant(t, ctx, tenantB)
	svc := gdpr.NewService(testPool, time.Nanosecond)

	if _, err := svc.Request(ctx, gdpr.CreateInput{TenantID: tenantA, UserID: victimID}); err == nil {
		t.Fatal("cross-tenant purge request was accepted")
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO "user".purge_requests (tenant_id, user_id, grace_until)
		VALUES ($1, $2, NOW() - INTERVAL '1 minute')
	`, tenantA, victimID); err == nil {
		t.Fatal("database accepted a mismatched purge tenant and user")
	}

	if _, err := testPool.Exec(ctx, `ALTER TABLE "user".purge_requests DISABLE TRIGGER ALL`); err != nil {
		t.Fatalf("disable purge constraint trigger: %v", err)
	}
	var requestID uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO "user".purge_requests (tenant_id, user_id, grace_until)
		VALUES ($1, $2, NOW() - INTERVAL '1 minute') RETURNING id
	`, tenantA, victimID).Scan(&requestID)
	if _, enableErr := testPool.Exec(ctx, `ALTER TABLE "user".purge_requests ENABLE TRIGGER ALL`); enableErr != nil {
		t.Fatalf("re-enable purge constraint trigger: %v", enableErr)
	}
	if err != nil {
		t.Fatalf("inject malformed legacy purge row: %v", err)
	}
	defer testPool.Exec(ctx, `DELETE FROM "user".purge_requests WHERE id = $1`, requestID) //nolint:errcheck

	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("purge sweep: %v", err)
	}
	var status, email string
	if err := testPool.QueryRow(ctx, `SELECT status FROM "user".purge_requests WHERE id = $1`, requestID).Scan(&status); err != nil {
		t.Fatalf("load purge request: %v", err)
	}
	if status != "quarantined" {
		t.Fatalf("malformed request status = %q, want quarantined", status)
	}
	if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, victimID).Scan(&email); err != nil {
		t.Fatalf("load victim: %v", err)
	}
	if email == "" || email[:min(len(email), len("redacted-"))] == "redacted-" {
		t.Fatalf("cross-tenant victim was modified: email=%q", email)
	}
}
