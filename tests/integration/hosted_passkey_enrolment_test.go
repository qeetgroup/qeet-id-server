//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// hostedLoginOrigin is the hosted login's browser origin: the Origin of its API
// calls and the origin of its WebAuthn ceremonies.
const hostedLoginOrigin = "http://localhost:3003"

// signedInAPI is the signed-in passkey API shaped as the production router
// builds it: the CSRF middleware in front, then, inside /v1, the hosted-login
// session middleware ahead of RequireAuth. It also mounts one signed-in route
// the hosted login never calls, to show the session reaches nothing else.
type signedInAPI struct {
	auth    *auth.Service
	issuer  *tokens.Issuer
	passkey *passkey.Service
	handler http.Handler
}

func newSignedInAPI(t *testing.T) *signedInAPI {
	t.Helper()
	issuer := mustIssuer()
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	// Mirrors internal/bootstrap/dependencies.go, with the hosted login as the
	// ceremony origin.
	wa, err := webauthn.New(&webauthn.Config{
		RPID: pkRPID, RPDisplayName: pkRPName, RPOrigins: []string{hostedLoginOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	pk := passkey.NewService(testPool, wa, authSvc)
	pk.SetMethodPolicy(authpolicy.NewService(testPool))

	r := chi.NewRouter()
	r.Use(httpx.CSRF(httpx.CSRFConfig{AllowedOrigins: []string{hostedLoginOrigin}}))
	r.Route("/v1", func(r chi.Router) {
		r.Use(authSvc.LoginSessionAuth(bootstrap.LoginSessionRoutes()))
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		(&passkey.Handler{Service: pk}).Mount(r)
		r.Get("/auth/sessions", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})
	return &signedInAPI{auth: authSvc, issuer: issuer, passkey: pk, handler: r}
}

// caller is how a request proves who it is: a browser holding a hosted-login
// session (with the CSRF cookie it echoes and its Origin), or a bearer token.
type caller struct {
	session string // qe_ls cookie; "" sends none
	csrf    string // qe_csrf cookie, echoed as X-CSRF-Token; "" sends neither
	origin  string
	bearer  string // Authorization: Bearer; "" sends none
}

func (c caller) apply(req *http.Request) {
	if c.session != "" {
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: c.session})
	}
	if c.csrf != "" {
		req.AddCookie(&http.Cookie{Name: "qe_csrf", Value: c.csrf})
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
}

// signIn starts a hosted-login session for userID, as a password, passkey or
// social sign-in on the hosted login does, and returns that browser.
func (a *signedInAPI) signIn(t *testing.T, ctx context.Context, userID uuid.UUID) caller {
	t.Helper()
	raw, err := a.auth.CreateLoginSession(ctx, userID, "203.0.113.7", uaChromeMac)
	if err != nil {
		t.Fatalf("create hosted-login session: %v", err)
	}
	return caller{session: raw, csrf: "csrf-" + uuid.NewString(), origin: hostedLoginOrigin}
}

// bearerFor returns an API client holding an access token for userID in
// tenantID (uuid.Nil = no organisation).
func (a *signedInAPI) bearerFor(t *testing.T, userID, tenantID uuid.UUID) caller {
	t.Helper()
	tok, _, err := a.issuer.IssueAccess(userID, tenantID, uuid.New(), "")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	return caller{bearer: tok}
}

func (a *signedInAPI) call(t *testing.T, c caller, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", uaChromeMac)
	c.apply(req)
	rr := httptest.NewRecorder()
	a.handler.ServeHTTP(rr, req)
	return rr
}

// beginEnrolment starts an enrolment as c and answers it with a new virtual
// authenticator, returning the ceremony id and the attestation to finish with.
func (a *signedInAPI) beginEnrolment(t *testing.T, c caller) (uuid.UUID, json.RawMessage) {
	t.Helper()
	begin := a.call(t, c, http.MethodPost, "/v1/passkeys/register/begin", nil)
	if begin.Code != http.StatusOK {
		t.Fatalf("register begin: status %d, body %s", begin.Code, begin.Body)
	}
	var started struct {
		SessionID uuid.UUID `json:"session_id"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	options, err := virtualwebauthn.ParseAttestationOptions(begin.Body.String())
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: hostedLoginOrigin}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options)
	return started.SessionID, json.RawMessage(attestation)
}

// finishEnrolment posts the attestation with any extra body fields.
func (a *signedInAPI) finishEnrolment(t *testing.T, c caller, sessionID uuid.UUID, attestation json.RawMessage, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"session_id": sessionID, "credential": attestation}
	for k, v := range extra {
		body[k] = v
	}
	return a.call(t, c, http.MethodPost, "/v1/passkeys/register/finish", body)
}

// passkeyList is GET /v1/passkeys as c.
type passkeyList struct {
	Items []struct {
		ID   uuid.UUID `json:"id"`
		Name *string   `json:"name"`
	} `json:"items"`
	EnrollmentAllowed *bool `json:"enrollment_allowed"`
}

func (a *signedInAPI) list(t *testing.T, c caller) passkeyList {
	t.Helper()
	rr := a.call(t, c, http.MethodGet, "/v1/passkeys", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list passkeys: status %d, body %s", rr.Code, rr.Body)
	}
	var out passkeyList
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out
}

func passkeyCount(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.passkey_credentials WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count passkeys: %v", err)
	}
	return n
}

func setPasskeyPolicy(t *testing.T, ctx context.Context, tenantID uuid.UUID, enabled bool) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, passkey_enabled) VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET passkey_enabled = EXCLUDED.passkey_enabled
	`, tenantID, enabled); err != nil {
		t.Fatalf("set passkey policy: %v", err)
	}
}

func createUserWithoutTenant(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (email) VALUES ($1) RETURNING id`,
		uniqueSlug("notenant")+"@example.com").Scan(&id); err != nil {
		t.Fatalf("create user without an organisation: %v", err)
	}
	return id
}

// TestHostedLoginPasskeyEnrolment: a user signed in to the hosted login adds a
// passkey with the hosted-login session cookie. Mutations carry the CSRF
// double-submit token, the passkey belongs to the session's user and their
// organisation, and the session reaches only the enrolment, list and rename
// routes.
func TestHostedLoginPasskeyEnrolment(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	api := newSignedInAPI(t)

	t.Run("the hosted-login session enrols a passkey for its own user and organisation", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("hostedpk"))
		userID := createUserInTenant(t, ctx, tenantID)
		browser := api.signIn(t, ctx, userID)

		list := api.list(t, browser)
		if list.EnrollmentAllowed == nil || !*list.EnrollmentAllowed || len(list.Items) != 0 {
			t.Fatalf("before enrolment: list = %+v, want no passkeys and enrolment offered", list)
		}
		sid, attestation := api.beginEnrolment(t, browser)
		if rr := api.finishEnrolment(t, browser, sid, attestation, nil); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish: status %d, body %s", rr.Code, rr.Body)
		}
		var owner, ownerTenant uuid.UUID
		if err := testPool.QueryRow(ctx, `
			SELECT c.user_id, u.tenant_id FROM auth.passkey_credentials c
			JOIN "user".users u ON u.id = c.user_id WHERE c.user_id = $1
		`, userID).Scan(&owner, &ownerTenant); err != nil {
			t.Fatalf("read stored passkey: %v", err)
		}
		if owner != userID || ownerTenant != tenantID {
			t.Errorf("passkey stored for user %v in organisation %v, want %v in %v", owner, ownerTenant, userID, tenantID)
		}
		if got := api.list(t, browser); len(got.Items) != 1 {
			t.Errorf("after enrolment the list shows %d passkeys, want 1", len(got.Items))
		}
	})

	t.Run("the owner cannot be named in the request", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("hostedpk"))
		userID := createUserInTenant(t, ctx, tenantID)
		victim := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		browser := api.signIn(t, ctx, userID)
		sid, attestation := api.beginEnrolment(t, browser)
		for _, extra := range []map[string]any{{"user_id": victim}, {"tenant_id": uuid.New()}} {
			if rr := api.finishEnrolment(t, browser, sid, attestation, extra); rr.Code != http.StatusBadRequest {
				t.Errorf("finish with %v: status %d, want 400", extra, rr.Code)
			}
		}
		if n := passkeyCount(t, ctx, victim); n != 0 {
			t.Errorf("the other user has %d passkeys, want 0", n)
		}
		if rr := api.finishEnrolment(t, browser, sid, attestation, nil); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish: status %d, body %s", rr.Code, rr.Body)
		}
		if n := passkeyCount(t, ctx, userID); n != 1 {
			t.Errorf("the signed-in user has %d passkeys, want 1", n)
		}
	})

	t.Run("a declined name gets a default and the passkey can be named later", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		browser := api.signIn(t, ctx, userID)
		sid, attestation := api.beginEnrolment(t, browser)
		if rr := api.finishEnrolment(t, browser, sid, attestation, map[string]any{"name": ""}); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish without a name: status %d, body %s", rr.Code, rr.Body)
		}
		list := api.list(t, browser)
		if len(list.Items) != 1 || deref(list.Items[0].Name) != "Chrome on macOS" {
			t.Fatalf("list = %+v, want one passkey named %q", list.Items, "Chrome on macOS")
		}
		rr := api.call(t, browser, http.MethodPatch, "/v1/passkeys/"+list.Items[0].ID.String(), map[string]any{"name": "Work laptop"})
		if rr.Code != http.StatusOK {
			t.Fatalf("rename: status %d, body %s", rr.Code, rr.Body)
		}
		if n := deref(api.list(t, browser).Items[0].Name); n != "Work laptop" {
			t.Errorf("name after renaming = %q, want %q", n, "Work laptop")
		}
	})

	t.Run("the session cannot remove a passkey", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		id := seedPasskey(t, ctx, userID, strPtr("Keep me"))
		rr := api.call(t, api.signIn(t, ctx, userID), http.MethodDelete, "/v1/passkeys/"+id.String(), nil)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("remove with the hosted-login session: status %d, want 401", rr.Code)
		}
		if n := passkeyCount(t, ctx, userID); n != 1 {
			t.Errorf("passkeys after the refused removal = %d, want 1", n)
		}
	})

	t.Run("other signed-in routes refuse the session", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		if rr := api.call(t, api.signIn(t, ctx, userID), http.MethodGet, "/v1/auth/sessions", nil); rr.Code != http.StatusUnauthorized {
			t.Errorf("GET /v1/auth/sessions with the hosted-login session: status %d, want 401", rr.Code)
		}
	})

	t.Run("mutations need the CSRF token and an allowed origin", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		browser := api.signIn(t, ctx, userID)
		id := seedPasskey(t, ctx, userID, strPtr("Keep me"))

		noToken := browser
		noToken.csrf = ""
		otherSite := browser
		otherSite.origin = "https://evil.example"
		for name, c := range map[string]caller{"no CSRF token": noToken, "another origin": otherSite} {
			if rr := api.call(t, c, http.MethodPost, "/v1/passkeys/register/begin", nil); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "csrf_failed") {
				t.Errorf("%s: register begin status %d body %s, want 403 csrf_failed", name, rr.Code, rr.Body)
			}
			if rr := api.call(t, c, http.MethodPost, "/v1/passkeys/register/finish", map[string]any{"session_id": uuid.New()}); rr.Code != http.StatusForbidden {
				t.Errorf("%s: register finish status %d, want 403", name, rr.Code)
			}
			if rr := api.call(t, c, http.MethodPatch, "/v1/passkeys/"+id.String(), map[string]any{"name": "Hijacked"}); rr.Code != http.StatusForbidden {
				t.Errorf("%s: rename status %d, want 403", name, rr.Code)
			}
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Keep me" {
			t.Errorf("name = %q, want it unchanged", n)
		}
		var ceremonies int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.webauthn_sessions WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
			t.Errorf("ceremonies started without a CSRF token = %d (err %v), want 0", ceremonies, err)
		}
	})

	t.Run("an unknown, expired or ended session is refused", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		expired := api.signIn(t, ctx, userID)
		if _, err := testPool.Exec(ctx, `UPDATE auth.login_sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`,
			tokens.HashRefresh(expired.session)); err != nil {
			t.Fatalf("expire session: %v", err)
		}
		ended := api.signIn(t, ctx, userID)
		if err := api.auth.RevokeLoginSession(ctx, ended.session); err != nil {
			t.Fatalf("end session: %v", err)
		}
		unknown := api.signIn(t, ctx, userID)
		unknown.session = "not-a-session"
		none := api.signIn(t, ctx, userID)
		none.session = ""
		for name, c := range map[string]caller{"unknown": unknown, "expired": expired, "ended": ended, "missing": none} {
			if rr := api.call(t, c, http.MethodGet, "/v1/passkeys", nil); rr.Code != http.StatusUnauthorized {
				t.Errorf("%s session: list status %d, want 401", name, rr.Code)
			}
			if rr := api.call(t, c, http.MethodPost, "/v1/passkeys/register/begin", nil); rr.Code != http.StatusUnauthorized {
				t.Errorf("%s session: register begin status %d, want 401", name, rr.Code)
			}
		}
	})

	t.Run("a suspended user's session is refused", func(t *testing.T) {
		userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("hostedpk")))
		browser := api.signIn(t, ctx, userID)
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, userID); err != nil {
			t.Fatalf("suspend user: %v", err)
		}
		if rr := api.call(t, browser, http.MethodPost, "/v1/passkeys/register/begin", nil); rr.Code != http.StatusUnauthorized {
			t.Errorf("register begin for a suspended user: status %d, want 401", rr.Code)
		}
	})
}

// TestPasskeyEnrolmentCeremonyState: a ceremony is single-use and bound to the
// user it was started for, whether the user enrols with a bearer token or with
// the hosted-login session. Each case answers with a genuine attestation, so the
// refusal comes from the ceremony state, not from a malformed credential.
func TestPasskeyEnrolmentCeremonyState(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	api := newSignedInAPI(t)

	for _, kind := range []string{"bearer token", "hosted-login session"} {
		as := func(t *testing.T, userID, tenantID uuid.UUID) caller {
			if kind == "bearer token" {
				return api.bearerFor(t, userID, tenantID)
			}
			return api.signIn(t, ctx, userID)
		}

		t.Run(kind+": an expired ceremony is refused and nothing is stored", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkstate"))
			userID := createUserInTenant(t, ctx, tenantID)
			c := as(t, userID, tenantID)
			sid, attestation := api.beginEnrolment(t, c)
			if _, err := testPool.Exec(ctx, `UPDATE auth.webauthn_sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, sid); err != nil {
				t.Fatalf("expire ceremony: %v", err)
			}
			rr := api.finishEnrolment(t, c, sid, attestation, nil)
			if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "auth.session_expired" {
				t.Errorf("finish an expired ceremony: status %d code %q, want 400 auth.session_expired", rr.Code, errorCode(t, rr))
			}
			if n := passkeyCount(t, ctx, userID); n != 0 {
				t.Errorf("passkeys stored = %d, want 0", n)
			}
		})

		t.Run(kind+": a ceremony cannot be finished twice", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkstate"))
			userID := createUserInTenant(t, ctx, tenantID)
			c := as(t, userID, tenantID)
			sid, attestation := api.beginEnrolment(t, c)
			if rr := api.finishEnrolment(t, c, sid, attestation, nil); rr.Code != http.StatusNoContent {
				t.Fatalf("first finish: status %d, body %s", rr.Code, rr.Body)
			}
			rr := api.finishEnrolment(t, c, sid, attestation, nil)
			if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "auth.session_expired" {
				t.Errorf("second finish: status %d code %q, want 400 auth.session_expired", rr.Code, errorCode(t, rr))
			}
			if n := passkeyCount(t, ctx, userID); n != 1 {
				t.Errorf("passkeys stored = %d, want 1", n)
			}
		})

		t.Run(kind+": another user's ceremony is refused", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkstate"))
			owner := createUserInTenant(t, ctx, tenantID)
			other := createUserInTenant(t, ctx, tenantID)
			sid, attestation := api.beginEnrolment(t, as(t, owner, tenantID))
			rr := api.finishEnrolment(t, as(t, other, tenantID), sid, attestation, nil)
			if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "passkey.session_mismatch" {
				t.Errorf("finish another user's ceremony: status %d code %q, want 400 passkey.session_mismatch", rr.Code, errorCode(t, rr))
			}
			for _, u := range []uuid.UUID{owner, other} {
				if n := passkeyCount(t, ctx, u); n != 0 {
					t.Errorf("passkeys stored for %v = %d, want 0", u, n)
				}
			}
		})
	}
}

// TestPasskeyEnrolmentFollowsTenantPolicy: enrolment is offered (the list's
// enrollment_allowed) and accepted (begin and finish) only when the user's
// organisation has passkeys switched on. A user without an organisation has no
// policy and is not restricted.
func TestPasskeyEnrolmentFollowsTenantPolicy(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	api := newSignedInAPI(t)

	for _, kind := range []string{"bearer token", "hosted-login session"} {
		as := func(t *testing.T, userID, tenantID uuid.UUID) caller {
			if kind == "bearer token" {
				return api.bearerFor(t, userID, tenantID)
			}
			return api.signIn(t, ctx, userID)
		}

		t.Run(kind+": passkeys switched off are neither offered nor accepted", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkpolicy"))
			setPasskeyPolicy(t, ctx, tenantID, false)
			userID := createUserInTenant(t, ctx, tenantID)
			c := as(t, userID, tenantID)
			if list := api.list(t, c); list.EnrollmentAllowed == nil || *list.EnrollmentAllowed {
				t.Errorf("enrollment_allowed = %v, want false", list.EnrollmentAllowed)
			}
			rr := api.call(t, c, http.MethodPost, "/v1/passkeys/register/begin", nil)
			if rr.Code != http.StatusForbidden || errorCode(t, rr) != "passkey.disabled" {
				t.Errorf("register begin: status %d code %q, want 403 passkey.disabled", rr.Code, errorCode(t, rr))
			}
		})

		t.Run(kind+": a ceremony begun before passkeys were switched off cannot be finished", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkpolicy"))
			userID := createUserInTenant(t, ctx, tenantID)
			c := as(t, userID, tenantID)
			sid, attestation := api.beginEnrolment(t, c)
			setPasskeyPolicy(t, ctx, tenantID, false)
			rr := api.finishEnrolment(t, c, sid, attestation, nil)
			if rr.Code != http.StatusForbidden || errorCode(t, rr) != "passkey.disabled" {
				t.Errorf("register finish: status %d code %q, want 403 passkey.disabled", rr.Code, errorCode(t, rr))
			}
			if n := passkeyCount(t, ctx, userID); n != 0 {
				t.Errorf("passkeys stored = %d, want 0", n)
			}
		})

		t.Run(kind+": passkeys switched on are offered and accepted", func(t *testing.T) {
			tenantID := createTenant(t, ctx, uniqueSlug("pkpolicy"))
			setPasskeyPolicy(t, ctx, tenantID, true)
			userID := createUserInTenant(t, ctx, tenantID)
			c := as(t, userID, tenantID)
			if list := api.list(t, c); list.EnrollmentAllowed == nil || !*list.EnrollmentAllowed {
				t.Errorf("enrollment_allowed = %v, want true", list.EnrollmentAllowed)
			}
			sid, attestation := api.beginEnrolment(t, c)
			if rr := api.finishEnrolment(t, c, sid, attestation, nil); rr.Code != http.StatusNoContent {
				t.Errorf("register finish: status %d, body %s", rr.Code, rr.Body)
			}
		})

		t.Run(kind+": a user without an organisation is not restricted", func(t *testing.T) {
			userID := createUserWithoutTenant(t, ctx)
			c := as(t, userID, uuid.Nil)
			if list := api.list(t, c); list.EnrollmentAllowed == nil || !*list.EnrollmentAllowed {
				t.Errorf("enrollment_allowed = %v, want true", list.EnrollmentAllowed)
			}
			sid, attestation := api.beginEnrolment(t, c)
			if rr := api.finishEnrolment(t, c, sid, attestation, nil); rr.Code != http.StatusNoContent {
				t.Errorf("register finish: status %d, body %s", rr.Code, rr.Body)
			}
		})
	}
}
