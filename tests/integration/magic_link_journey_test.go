//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// A magic link can be asked for from the console's sign-in page and from an
// organisation's hosted sign-in page, and signs in where it was asked for:
// the console exchanges it for tokens; the hosted login opens its session and
// continues the journey. Asking answers the same for any address and sends
// nothing to one without an account; a used or expired link can be replaced
// without typing the address again; requests are bounded per address.

type magicFixture struct {
	sender *captureSender
	svc    *recovery.Service
	router http.Handler
}

func newMagicFixture(t *testing.T) *magicFixture {
	t.Helper()
	f := &magicFixture{sender: &captureSender{}}
	f.svc = newRecovery(f.sender)
	f.svc.SetHostedLogin("http://login.test")
	f.svc.SetMagicLinkLimits(ratelimit.New(1.0/300, 3), ratelimit.New(1.0/60, 50))
	authSvc, _ := newAuth()
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		(&recovery.Handler{Service: f.svc, AuthService: authSvc}).Mount(r)
	})
	f.router = r
	return f
}

func (f *magicFixture) post(path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// lastLink is the URL of the newest email and its token.
func (f *magicFixture) lastLink(t *testing.T) (*url.URL, string) {
	t.Helper()
	m, ok := f.sender.last()
	if !ok {
		t.Fatal("no email was sent")
	}
	u, err := url.Parse(m.TemplateVariables["magic_url"])
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	return u, u.Query().Get("token")
}

func tenantlessUser(t *testing.T, ctx context.Context) (uuid.UUID, string) {
	t.Helper()
	email := uniqueSlug("magic") + "@example.com"
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (tenant_id, email) VALUES (NULL, $1) RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id, email
}

// TestConsoleMagicLink covers: a link asked for from the console signs the
// account in there; a used link is refused and can be replaced without the
// address; the replacement works; an address without an account gets the same
// answer and no email.
func TestConsoleMagicLink(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicFixture(t)
	me, email := tenantlessUser(t, ctx)

	known := f.post("/v1/auth/magic-link/start", map[string]string{"email": email})
	u, token := f.lastLink(t)
	if known.Code != http.StatusOK || u.Host != "app.test" || u.Path != "/magic" {
		t.Fatalf("console request: %d %s, link %s", known.Code, known.Body.String(), u)
	}
	sent := f.sender.count()
	unknown := f.post("/v1/auth/magic-link/start", map[string]string{"email": uniqueSlug("nobody") + "@example.com"})
	if unknown.Code != known.Code || unknown.Body.String() != known.Body.String() || f.sender.count() != sent {
		t.Errorf("unknown address: %d %s (emails %d → %d), want the same answer and no email", unknown.Code, unknown.Body.String(), sent, f.sender.count())
	}

	rr := f.post("/v1/auth/magic-link/consume", map[string]string{"token": token})
	var pair struct {
		UserID      uuid.UUID `json:"user_id"`
		AccessToken string    `json:"access_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &pair)
	if rr.Code != http.StatusOK || pair.UserID != me || pair.AccessToken == "" {
		t.Fatalf("console exchange: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.post("/v1/auth/magic-link/consume", map[string]string{"token": token}); errorCode(t, rr) != errs.CodeRecoveryLinkUsed {
		t.Fatalf("second exchange: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.post("/v1/auth/magic-link/resend", map[string]string{"token": token}); rr.Code != http.StatusOK {
		t.Fatalf("resend: %d %s", rr.Code, rr.Body.String())
	}
	_, replacement := f.lastLink(t)
	if replacement == token {
		t.Fatal("no new link was sent")
	}
	if rr := f.post("/v1/auth/magic-link/consume", map[string]string{"token": replacement}); rr.Code != http.StatusOK {
		t.Fatalf("replacement link: %d %s", rr.Code, rr.Body.String())
	}
}

// TestHostedMagicLinkContinuesTheJourney covers: a link asked for from an
// organisation's hosted sign-in page opens the hosted login, opens its session
// and returns to the journey; it is not exchangeable by the console, nor a
// console link by the hosted login; it expires; an organisation with magic
// links off refuses to issue one, and a console request for its member sends
// nothing.
func TestHostedMagicLinkContinuesTheJourney(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicFixture(t)
	tenantID := createTenant(t, ctx, uniqueSlug("magichosted"))
	email := uniqueSlug("member") + "@example.com"
	createTenantUser(t, ctx, tenantID, email)
	journey := "http://example.com/v1/oauth/authorize?client_id=app&state=s"
	ask := func() string {
		t.Helper()
		rr := f.post("/v1/auth/magic-link/start", map[string]string{
			"tenant_id": tenantID.String(), "email": email, "app": "hosted_login", "return_to": journey,
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("hosted request: %d %s", rr.Code, rr.Body.String())
		}
		u, token := f.lastLink(t)
		if u.Host != "login.test" || u.Path != "/magic" || u.Query().Get("return_to") != journey {
			t.Fatalf("hosted link %s", u)
		}
		return token
	}

	token := ask()
	if rr := f.post("/v1/auth/magic-link/consume", map[string]string{"token": token}); errorCode(t, rr) != errs.CodeMagicLinkInvalid {
		t.Errorf("the console exchanged a hosted link: %d %s", rr.Code, rr.Body.String())
	}
	rr := f.post("/v1/auth/magic-link/session", map[string]string{"token": token})
	var out struct {
		ReturnTo string `json:"return_to"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.ReturnTo != journey || !strings.Contains(rr.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("hosted exchange: %d %s cookie %q", rr.Code, rr.Body.String(), rr.Header().Get("Set-Cookie"))
	}

	expired := ask()
	if _, err := testPool.Exec(ctx, `UPDATE auth.magic_links SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, codes.Hash(expired)); err != nil {
		t.Fatal(err)
	}
	if rr := f.post("/v1/auth/magic-link/session", map[string]string{"token": expired}); errorCode(t, rr) != errs.CodeRecoveryLinkExpired {
		t.Errorf("expired hosted link: %d %s", rr.Code, rr.Body.String())
	}

	f.post("/v1/auth/magic-link/start", map[string]string{"email": email})
	_, consoleToken := f.lastLink(t)
	if rr := f.post("/v1/auth/magic-link/session", map[string]string{"token": consoleToken}); errorCode(t, rr) != errs.CodeMagicLinkInvalid {
		t.Errorf("the hosted login exchanged a console link: %d %s", rr.Code, rr.Body.String())
	}

	setSignInMethods(t, ctx, tenantID, true, true, false, 15)
	f = newMagicFixture(t) // a fresh per-address bound
	if rr := f.post("/v1/auth/magic-link/start", map[string]string{"tenant_id": tenantID.String(), "email": email, "app": "hosted_login"}); errorCode(t, rr) != errs.CodeAuthMethodDisabled {
		t.Errorf("hosted request with magic links off: %d %s", rr.Code, rr.Body.String())
	}
	sent := f.sender.count()
	if rr := f.post("/v1/auth/magic-link/start", map[string]string{"email": email}); rr.Code != http.StatusOK || f.sender.count() != sent {
		t.Errorf("console request for a member of an organisation with magic links off: %d, emails %d → %d", rr.Code, sent, f.sender.count())
	}
}

// TestMagicLinkRequestsAreBounded: after three requests for one address the
// next is refused, whether or not the address has an account.
func TestMagicLinkRequestsAreBounded(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicFixture(t)
	_, email := tenantlessUser(t, ctx)
	for name, addr := range map[string]string{"registered": email, "unknown": uniqueSlug("nobody") + "@example.com"} {
		for i := 0; i < 3; i++ {
			if rr := f.post("/v1/auth/magic-link/start", map[string]string{"email": addr}); rr.Code != http.StatusOK {
				t.Fatalf("%s request %d: %d %s", name, i+1, rr.Code, rr.Body.String())
			}
		}
		if rr := f.post("/v1/auth/magic-link/start", map[string]string{"email": addr}); rr.Code != http.StatusTooManyRequests {
			t.Errorf("%s fourth request: %d, want 429", name, rr.Code)
		}
	}
}
