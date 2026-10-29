//go:build integration

package principal

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestClientCredentialsErrorsUseTheOAuthShape checks the client_credentials
// grant against real principals: wrong or unknown credentials are
// invalid_client, a disabled principal is unauthorized_client, and the right
// secret gets a token.
func TestClientCredentialsErrorsUseTheOAuthShape(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	p, secret, err := svc.Create(ctx, tx, CreateInput{TenantID: tenant, Name: "Reporting", Scopes: []string{}})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	(&Handler{Service: svc}).MountToken(router)
	cc := url.Values{"grant_type": {"client_credentials"}}
	id := p.ID.String()

	wantTokenError(t, tokenRequest(t, router, cc, id, "wrong-secret"), http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`)
	inForm := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"wrong-secret"}}
	wantTokenError(t, tokenRequest(t, router, inForm, "", ""), http.StatusUnauthorized, "invalid_client", "")
	wantTokenError(t, tokenRequest(t, router, cc, uuid.NewString(), secret), http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`)
	rec := tokenRequest(t, router, cc, id, secret)
	if rec.Code != http.StatusOK {
		t.Fatalf("token with the right secret = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var issued struct {
		ExpiresIn int64 `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || issued.ExpiresIn <= 0 {
		t.Errorf("token response %s: want a positive expires_in (err %v)", rec.Body.String(), err)
	}

	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || !live {
		t.Errorf("an enabled principal: live %v, %v; want live", live, err)
	}
	if live, err := svc.PrincipalLive(ctx, uuid.New()); err != nil || live {
		t.Errorf("an unknown principal: live %v, %v; want not live", live, err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.service_principals SET disabled_at = NOW() WHERE id = $1 AND tenant_id = $2`, p.ID, tenant); err != nil {
		t.Fatal(err)
	}
	wantTokenError(t, tokenRequest(t, router, cc, id, secret), http.StatusBadRequest, "unauthorized_client", "")
	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || live {
		t.Errorf("a disabled principal: live %v, %v; want not live", live, err)
	}
}

// TestRotatedSecretsOverlapAndPrincipalsEnable checks that a rotated
// principal's old secret goes on getting tokens until its overlap ends, that a
// token issued is noted as its last use, and that a disabled principal can be
// enabled again.
func TestRotatedSecretsOverlapAndPrincipalsEnable(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	p, oldSecret, err := svc.Create(ctx, tx, CreateInput{TenantID: tenant, Name: "Reporting", Description: "Nightly export", Scopes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Description != "Nightly export" {
		t.Errorf("created description = %q", p.Description)
	}
	system := audit.Actor{Type: "system"}
	newSecret, until, err := svc.RotateSecret(ctx, tenant, p.ID, time.Hour, system)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for name, secret := range map[string]string{"old": oldSecret, "new": newSecret} {
		if _, err := svc.IssueClientCredentials(ctx, p.ID.String(), secret); err != nil {
			t.Errorf("the %s secret during the overlap: %v", name, err)
		}
	}
	list, err := svc.List(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v, %v", list, err)
	}
	if got := list[0]; got.Description != "Nightly export" || got.LastUsedAt == nil ||
		got.PreviousSecretExpiresAt == nil || !got.PreviousSecretExpiresAt.Equal(until.Truncate(time.Microsecond)) {
		t.Errorf("listed principal %+v: want its description, a last use and the overlap's end %s", got, until)
	}
	if _, _, err := svc.RotateSecret(ctx, tenant, p.ID, 0, system); err != nil {
		t.Fatalf("rotate with no overlap: %v", err)
	}
	if _, err := svc.IssueClientCredentials(ctx, p.ID.String(), newSecret); !errors.Is(err, errs.ErrPrincipalInvalidCredentials) {
		t.Errorf("a secret rotated with no overlap: %v, want %v", err, errs.ErrPrincipalInvalidCredentials)
	}
	if _, _, err := svc.RotateSecret(ctx, dbtest.Tenant(t), p.ID, time.Hour, system); !errors.Is(err, errs.ErrPrincipalNotFound) {
		t.Errorf("rotate from another tenant: %v, want %v", err, errs.ErrPrincipalNotFound)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, _, err := svc.Disable(ctx, tx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(ctx, dbtest.Tenant(t), p.ID, system); !errors.Is(err, errs.ErrPrincipalNotFound) {
		t.Errorf("enable from another tenant: %v, want %v", err, errs.ErrPrincipalNotFound)
	}
	if err := svc.Enable(ctx, tenant, p.ID, system); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || !live {
		t.Errorf("an enabled principal: live %v, %v", live, err)
	}
}
