//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// The step-up gate in front of sensitive routes: a route that changes the
// person's own factors needs a step-up only while they hold a factor their
// organisation counts, every other listed route always does, machines (no
// session) can never pass, and a fresh hosted-login sign-in counts as one.

func gateRouter(svc *mfa.Service, p *httpx.Principal) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		})
	})
	r.Use(svc.StepUpGate(map[string]mfa.StepUpRule{
		"POST /v1/mfa/otp/factors": mfa.StepUpWhenFactorHeld,
		"POST /v1/api-keys":        mfa.StepUpAlways,
	}))
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	r.Post("/v1/mfa/otp/factors", ok)
	r.Post("/v1/api-keys", ok)
	r.Get("/v1/api-keys", ok)
	return r
}

func gateStatus(h http.Handler, method, path string) int {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr.Code
}

func userPrincipal(userID, tenantID uuid.UUID, sessionID *uuid.UUID) *httpx.Principal {
	uid, tid := userID, tenantID
	return &httpx.Principal{UserID: &uid, TenantID: &tid, SessionID: sessionID, ActorType: "user", Subject: uid.String()}
}

// TestStepUpGateWhenFactorHeld: a first factor needs no step-up; once one is
// held, changing factors does, and the session's step-up lets it through.
func TestStepUpGateWhenFactorHeld(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("gate-held"))
	userID := createUserInTenant(t, ctx, tenantID)
	sess := openSession(t, ctx, userID, tenantID)
	h := gateRouter(svc, userPrincipal(userID, tenantID, &sess))

	if got := gateStatus(h, http.MethodPost, "/v1/mfa/otp/factors"); got != http.StatusNoContent {
		t.Fatalf("a first factor = %d, want 204 without a step-up", got)
	}
	holdApp(t, ctx, svc, userID)
	if got := gateStatus(h, http.MethodPost, "/v1/mfa/otp/factors"); got != http.StatusForbidden {
		t.Fatalf("adding a factor while one is held = %d, want 403", got)
	}
	recordStepUp(t, ctx, svc, userID, sess, "totp")
	if got := gateStatus(h, http.MethodPost, "/v1/mfa/otp/factors"); got != http.StatusNoContent {
		t.Fatalf("after the session's step-up = %d, want 204", got)
	}
	if got := gateStatus(h, http.MethodGet, "/v1/api-keys"); got != http.StatusNoContent {
		t.Fatalf("an unlisted route = %d, want 204", got)
	}
}

// TestStepUpGateCountsOnlyAcceptedFactors: a factor the organisation does not
// count for a step-up does not make one necessary, so a person is never asked
// for a step-up they cannot give.
func TestStepUpGateCountsOnlyAcceptedFactors(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("gate-accepted"))
	userID := createUserInTenant(t, ctx, tenantID)
	sess := openSession(t, ctx, userID, tenantID)
	holdApp(t, ctx, svc, userID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, step_up_methods) VALUES ($1, ARRAY['webauthn'])`, tenantID); err != nil {
		t.Fatal(err)
	}
	h := gateRouter(svc, userPrincipal(userID, tenantID, &sess))
	if got := gateStatus(h, http.MethodPost, "/v1/mfa/otp/factors"); got != http.StatusNoContent {
		t.Fatalf("holding only a factor the organisation does not count = %d, want 204", got)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE tenant.security_policies SET step_up_methods = ARRAY['totp'] WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if got := gateStatus(h, http.MethodPost, "/v1/mfa/otp/factors"); got != http.StatusForbidden {
		t.Fatalf("holding a counted factor = %d, want 403", got)
	}
}

// TestStepUpGateRefusesMachines: a principal without a session cannot step
// up, so it is refused on every always-gated route.
func TestStepUpGateRefusesMachines(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("gate-machine"))
	userID := createUserInTenant(t, ctx, tenantID)
	p := userPrincipal(userID, tenantID, nil)
	p.ActorType = "api_key"
	if got := gateStatus(gateRouter(svc, p), http.MethodPost, "/v1/api-keys"); got != http.StatusForbidden {
		t.Fatalf("an API key minting a key = %d, want 403", got)
	}
}

// TestStepUpGateAcceptsAFreshHostedSignIn: a hosted-login principal (no API
// session) passes within the organisation's window after its sign-in, and not
// after it, nor where the organisation limits which factors count.
func TestStepUpGateAcceptsAFreshHostedSignIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("gate-hosted"))
	userID := createUserInTenant(t, ctx, tenantID)
	hosted := func(ago time.Duration) http.Handler {
		at := time.Now().Add(-ago)
		p := userPrincipal(userID, tenantID, nil)
		p.SignedInAt = &at
		return gateRouter(svc, p)
	}
	if got := gateStatus(hosted(time.Minute), http.MethodPost, "/v1/api-keys"); got != http.StatusNoContent {
		t.Fatalf("a sign-in a minute ago = %d, want 204", got)
	}
	if got := gateStatus(hosted(6*time.Minute), http.MethodPost, "/v1/api-keys"); got != http.StatusForbidden {
		t.Fatalf("a sign-in six minutes ago = %d, want 403", got)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, step_up_methods) VALUES ($1, ARRAY['webauthn'])`, tenantID); err != nil {
		t.Fatal(err)
	}
	if got := gateStatus(hosted(time.Minute), http.MethodPost, "/v1/api-keys"); got != http.StatusForbidden {
		t.Fatalf("a fresh sign-in where only some factors count = %d, want 403", got)
	}
}
