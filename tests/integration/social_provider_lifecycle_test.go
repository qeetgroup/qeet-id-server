//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An organisation's social providers are managed for their whole life:
// switched off (and kept off by later saves), switched on, a secret replaced
// without resubmitting the rest, and removed — refused while someone can sign
// in only through the provider. Secrets are never read back, another
// organisation's provider cannot be touched, and a switched-off or removed
// provider reads to a signing-in user exactly like one never set up.

type providerAdmin struct {
	*closedRegFixture
	router http.Handler
}

func newProviderAdmin(t *testing.T, ctx context.Context) *providerAdmin {
	t.Helper()
	f := &providerAdmin{closedRegFixture: newClosedRegFixture(t, ctx, true)}
	f.router = f.routerFor(createUserInTenant(t, ctx, f.tenantID), f.tenantID)
	return f
}

func (f *providerAdmin) routerFor(userID, tenantID uuid.UUID) http.Handler {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(withPrincipal(userID, tenantID))
		(&social.Handler{Service: f.svc}).Mount(r)
	})
	return r
}

func callJSON(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func (f *providerAdmin) secretCiphertext(t *testing.T, ctx context.Context, tenantID uuid.UUID, provider string) []byte {
	t.Helper()
	var ct []byte
	if err := testPool.QueryRow(ctx, `SELECT client_secret_ct FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2`,
		tenantID, provider).Scan(&ct); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	return ct
}

func (f *providerAdmin) enabled(t *testing.T, ctx context.Context) bool {
	t.Helper()
	var on bool
	if err := testPool.QueryRow(ctx, `SELECT enabled FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2`,
		f.tenantID, f.provider).Scan(&on); err != nil {
		t.Fatalf("read provider: %v", err)
	}
	return on
}

func (f *providerAdmin) signInRefusal(ctx context.Context, provider string) error {
	_, err := f.svc.BeginLogin(ctx, provider, f.tenantID.String(), "http://api.local/v1/social/"+provider+"/callback", "")
	return err
}

func providerAudits(t *testing.T, ctx context.Context, tenantID uuid.UUID) []string {
	t.Helper()
	rows, err := testPool.Query(ctx, `
		SELECT action || COALESCE(':' || (metadata->>'secret_replaced'), '') FROM audit.events
		WHERE tenant_id = $1 AND action LIKE 'social_provider.%' ORDER BY created_at, id`, tenantID)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

// TestSocialProviderSwitchOffAndSecrets covers: switching a provider off stops
// sign-in through it (with the never-set-up answer) and lists it off; saving
// other fields — the whole record without a secret, or one field — keeps it
// off and keeps the stored secret; switching it on restores sign-in; replacing
// the secret changes only that provider's; the secret is never read back;
// each change is audited.
func TestSocialProviderSwitchOffAndSecrets(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newProviderAdmin(t, ctx)
	if _, err := f.svc.UpsertProvider(ctx, social.CreateProviderInput{
		TenantID: f.tenantID, Provider: "otherprov", ClientID: "other", ClientSecret: "other-secret",
		DiscoveryURL: f.idp.URL + "/.well-known/openid-configuration",
	}); err != nil {
		t.Fatalf("second provider: %v", err)
	}
	path := "/v1/social/providers/" + f.provider
	original := f.secretCiphertext(t, ctx, f.tenantID, f.provider)
	other := f.secretCiphertext(t, ctx, f.tenantID, "otherprov")

	if rr := callJSON(f.router, http.MethodPatch, path, map[string]any{"enabled": false}); rr.Code != http.StatusOK {
		t.Fatalf("switch off: %d %s", rr.Code, rr.Body.String())
	}
	off := f.signInRefusal(ctx, f.provider)
	never := f.signInRefusal(ctx, "neverset")
	if !errors.Is(off, errs.ErrSocialProviderNotConfigured) || !errors.Is(never, errs.ErrSocialProviderNotConfigured) {
		t.Errorf("sign-in through a switched-off provider: %v; through one never set up: %v; want the same refusal", off, never)
	}
	if err := f.signInRefusal(ctx, "otherprov"); err != nil {
		t.Errorf("the organisation's other provider stopped working: %v", err)
	}

	rr := callJSON(f.router, http.MethodPost, "/v1/social/providers", map[string]any{
		"provider": f.provider, "client_id": "cid-2", "client_secret": "",
		"discovery_url": f.idp.URL + "/.well-known/openid-configuration",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("save without a secret: %d %s", rr.Code, rr.Body.String())
	}
	callJSON(f.router, http.MethodPatch, path, map[string]any{"client_id": "cid-3"})
	if f.enabled(t, ctx) {
		t.Error("saving other fields switched the provider back on")
	}
	if !bytes.Equal(f.secretCiphertext(t, ctx, f.tenantID, f.provider), original) {
		t.Error("a save without a secret replaced the stored one")
	}

	if rr := callJSON(f.router, http.MethodPatch, path, map[string]any{"enabled": true, "client_secret": "rotated-secret"}); rr.Code != http.StatusOK {
		t.Fatalf("switch on and rotate: %d %s", rr.Code, rr.Body.String())
	}
	if err := f.signInRefusal(ctx, f.provider); err != nil {
		t.Errorf("sign-in after switching back on: %v", err)
	}
	if bytes.Equal(f.secretCiphertext(t, ctx, f.tenantID, f.provider), original) {
		t.Error("the secret was not replaced")
	}
	if !bytes.Equal(f.secretCiphertext(t, ctx, f.tenantID, "otherprov"), other) {
		t.Error("replacing one provider's secret changed another's")
	}

	list := callJSON(f.router, http.MethodGet, "/v1/tenants/"+f.tenantID.String()+"/social/providers", nil)
	for _, leaked := range []string{"client_secret", "rotated-secret", "other-secret", "secret\""} {
		if strings.Contains(list.Body.String(), leaked) {
			t.Errorf("the provider list returns %q: %s", leaked, list.Body.String())
		}
	}

	got := strings.Join(providerAudits(t, ctx, f.tenantID), " ")
	for _, want := range []string{"social_provider.created", "social_provider.disabled", "social_provider.updated:false", "social_provider.enabled", "social_provider.updated:true"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %s (got %s)", want, got)
		}
	}
}

// TestSocialProviderRemoval covers: removal is refused while someone can sign
// in only through the provider, and allowed once they have another way in;
// the provider disappears, sign-in through it reads as never set up, the
// linked identity is kept, and the removal is audited. Another organisation
// cannot change or remove it.
func TestSocialProviderRemoval(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newProviderAdmin(t, ctx)
	path := "/v1/social/providers/" + f.provider

	someoneElse := f.routerFor(uuid.New(), createTenant(t, ctx, uniqueSlug("otherorg")))
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		if rr := callJSON(someoneElse, method, path, map[string]any{"enabled": false}); rr.Code != http.StatusNotFound {
			t.Errorf("%s from another organisation: %d %s, want 404", method, rr.Code, rr.Body.String())
		}
	}
	if !f.enabled(t, ctx) {
		t.Fatal("another organisation switched the provider off")
	}

	member := createUserInTenant(t, ctx, f.tenantID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
		VALUES ($1, $2, $3, $4, 'member@example.com')`, member, f.tenantID, f.provider, uniqueSlug("sub")); err != nil {
		t.Fatalf("link identity: %v", err)
	}
	rr := callJSON(f.router, http.MethodDelete, path, nil)
	var refused struct {
		Error struct {
			Code     string         `json:"code"`
			Metadata map[string]any `json:"metadata"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &refused)
	if rr.Code != http.StatusConflict || refused.Error.Code != errs.CodeSocialProviderInUse || refused.Error.Metadata["people"] != float64(1) {
		t.Fatalf("remove while someone depends on it: %d %s", rr.Code, rr.Body.String())
	}

	if _, err := testPool.Exec(ctx, `INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, 'x')`, member); err != nil {
		t.Fatalf("give another way in: %v", err)
	}
	if rr := callJSON(f.router, http.MethodDelete, path, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body.String())
	}
	list := callJSON(f.router, http.MethodGet, "/v1/tenants/"+f.tenantID.String()+"/social/providers", nil)
	if strings.Contains(list.Body.String(), f.provider) {
		t.Errorf("removed provider still listed: %s", list.Body.String())
	}
	if err := f.signInRefusal(ctx, f.provider); !errors.Is(err, errs.ErrSocialProviderNotConfigured) {
		t.Errorf("sign-in through a removed provider: %v", err)
	}
	var kept int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND provider = $2`, member, f.provider).Scan(&kept); err != nil || kept != 1 {
		t.Errorf("linked identity kept = %d (%v), want 1", kept, err)
	}
	if got := strings.Join(providerAudits(t, ctx, f.tenantID), " "); !strings.Contains(got, "social_provider.deleted") {
		t.Errorf("removal not audited: %s", got)
	}
}
