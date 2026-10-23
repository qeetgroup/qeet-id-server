//go:build integration

package principal

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.service_principals SET disabled_at = NOW() WHERE id = $1 AND tenant_id = $2`, p.ID, tenant); err != nil {
		t.Fatal(err)
	}
	wantTokenError(t, tokenRequest(t, router, cc, id, secret), http.StatusBadRequest, "unauthorized_client", "")
}
