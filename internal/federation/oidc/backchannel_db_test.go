//go:build integration

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// prompt is one out-of-band notice a Notifier was asked to deliver.
type prompt struct {
	tenantID, userID   uuid.UUID
	title, description string
}

// promptBox is a Notifier that keeps the prompts it is asked to deliver.
type promptBox struct {
	mu   sync.Mutex
	sent []prompt
}

// Notify records the prompt.
func (b *promptBox) Notify(_ context.Context, tenantID, userID uuid.UUID, _, title, description, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, prompt{tenantID: tenantID, userID: userID, title: title, description: description})
	return nil
}

// TestBackchannelFlow checks that only a confidential application with the
// CIBA grant starts a backchannel sign-in, for a person of its own
// organisation, who is prompted and alone decides it, once; and that polling
// answers pending, slow_down and access_denied, and an approval buys tokens once.
func TestBackchannelFlow(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	p := newProvider(t)
	prompts := &promptBox{}
	p.svc.SetNotifier(prompts)
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	colleague := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, otherTenant, otherTenant)
	kiosk, secret := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenant, Name: "Kiosk", GrantTypes: []string{grantTypeCIBA, "refresh_token"}})
	plain, plainSecret := registerClient(t, p.svc, tenant)
	public, _ := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenant, Type: "public"})
	hint := func(email string) url.Values {
		return url.Values{"login_hint": {email}, "scope": {"openid"}, "binding_message": {"Till 4"}}
	}
	start := func(user, pass string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, p.public, "/oauth/bc-authorize", form, user, pass)
	}

	for _, tc := range []struct {
		name, user, pass string
		form             url.Values
		want             string
	}{
		{"a public client", public.ClientID, "", hint(person.Email), errs.CodeOIDCClientAuthFailed},
		{"an application without the grant", plain.ClientID, plainSecret, hint(person.Email), "unauthorized_client"},
		{"a wrong secret", kiosk.ClientID, "wrong-secret", hint(person.Email), errs.CodeOIDCClientAuthFailed},
		{"a person of another organisation", kiosk.ClientID, secret, hint(outsider.Email), "unknown_user_id"},
		{"no login_hint", kiosk.ClientID, secret, url.Values{"scope": {"openid"}}, "invalid_request"},
		{"a scope the application may not have", kiosk.ClientID, secret, url.Values{"login_hint": {person.Email}, "scope": {"admin"}}, "invalid_scope"},
		{"a resource", kiosk.ClientID, secret, url.Values{"login_hint": {person.Email}, "resource": {resourceA}}, "invalid_target"},
	} {
		if rec := start(tc.user, tc.pass, tc.form); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("start with %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_ciba_requests WHERE tenant_id = $1`, tenant); n != 0 || len(prompts.sent) != 0 {
		t.Errorf("refused requests stored %d and prompted %d, want none", n, len(prompts.sent))
	}

	begin := func() string {
		t.Helper()
		rec := start(kiosk.ClientID, secret, hint(strings.ToUpper(person.Email)))
		var out CIBAAuthResponse
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusOK || out.AuthReqID == "" || out.Interval != cibaPollInterval {
			t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
		}
		return out.AuthReqID
	}
	collect := func(authReqID string) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, p.public, "/oauth/token-code", url.Values{"grant_type": {grantTypeCIBA}, "auth_req_id": {authReqID}}, kiosk.ClientID, secret)
	}
	// poll collects as a client that waited out the interval since its last poll.
	poll := func(authReqID string) *httptest.ResponseRecorder {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE auth.oidc_ciba_requests SET last_polled_at = last_polled_at - INTERVAL '1 minute'
			WHERE tenant_id = $1 AND auth_req_id_hash = $2`, tenant, codes.Hash(authReqID)); err != nil {
			t.Fatal(err)
		}
		return collect(authReqID)
	}
	pollError := func(authReqID string) string {
		t.Helper()
		code, _ := decodeTokenError(t, poll(authReqID))
		return code
	}
	asPerson := dbtest.Serve(dbtest.Principal(person.ID, tenant), p.mount)
	asColleague := dbtest.Serve(dbtest.Principal(colleague.ID, tenant), p.mount)
	pending := func(h http.Handler) []CIBAPendingRequest {
		t.Helper()
		var page struct {
			Items []CIBAPendingRequest `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/oauth/bc-authorize/pending", nil), &page)
		return page.Items
	}
	decide := func(h http.Handler, id uuid.UUID, approve bool) *httptest.ResponseRecorder {
		t.Helper()
		return dbtest.Do(t, h, http.MethodPost, "/oauth/bc-authorize/decision", map[string]any{"id": id, "approve": approve})
	}

	authReqID := begin()
	if len(prompts.sent) != 1 || prompts.sent[0].userID != person.ID || prompts.sent[0].tenantID != tenant || prompts.sent[0].description != "Till 4" {
		t.Errorf("prompts %+v, want one to the person in the organisation with the binding message", prompts.sent)
	}
	if got := pollError(authReqID); got != "authorization_pending" {
		t.Errorf("poll before approval: %s, want authorization_pending", got)
	}
	if got, _ := decodeTokenError(t, collect(authReqID)); got != "slow_down" {
		t.Errorf("poll again at once: %s, want slow_down", got)
	}
	if got := pending(asColleague); len(got) != 0 {
		t.Errorf("a colleague sees the person's requests: %+v", got)
	}
	mine := pending(asPerson)
	if len(mine) != 1 || mine[0].ClientName != "Kiosk" || mine[0].BindingMessage == nil || *mine[0].BindingMessage != "Till 4" {
		t.Fatalf("the person's pending requests %+v, want the kiosk's with its binding message", mine)
	}
	if rec := decide(asColleague, mine[0].ID, true); !strings.Contains(rec.Body.String(), errs.CodeOIDCCIBARequestNotOwned) {
		t.Errorf("a colleague approving: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(asPerson, mine[0].ID, true); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(asPerson, mine[0].ID, false); !strings.Contains(rec.Body.String(), errs.CodeOIDCCIBARequestAlreadyDecided) {
		t.Errorf("decide again: %d %s", rec.Code, rec.Body.String())
	}
	rec := poll(authReqID)
	var issued TokenResponse
	dbtest.Decode(t, rec, &issued)
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if rec.Code != http.StatusOK || err != nil || claims.UserID != person.ID || claims.ClientID != kiosk.ClientID || issued.IDToken == "" || issued.RefreshToken == "" {
		t.Fatalf("collect: %d %s, %v", rec.Code, rec.Body.String(), err)
	}
	if got := pollError(authReqID); got != "invalid_grant" {
		t.Errorf("collect twice: %s, want invalid_grant", got)
	}

	deniedID := begin()
	if rec := decide(asPerson, pending(asPerson)[0].ID, false); rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(deniedID); got != "access_denied" {
		t.Errorf("poll after denial: %s, want access_denied", got)
	}
}
