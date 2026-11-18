package httpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestEnforceOrganizationScope checks that a {organizationID} route admits only the caller's
// own organization (403 for another, 400 for a malformed id) and that routes without
// the param pass through.
func TestEnforceOrganizationScope(t *testing.T) {
	callerOrganization := uuid.New()
	otherOrganization := uuid.New()
	uid := uuid.New()

	// Mirror the production router structure exactly (nested Route + Group with
	// the guard as group middleware) — chi only populates {organizationID} for a
	// group-level middleware when routes are matched by a nested subrouter, so a
	// flat mux would not exercise the same code path the server uses.
	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						p := &httpx.Principal{UserID: &uid, OrganizationID: &callerOrganization}
						next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
					})
				})
				r.Use(httpx.EnforceOrganizationScope)
				ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
				r.Get("/organizations/{organizationID}/roles", ok)
				r.Get("/users/{id}", ok) // no organizationID param — must pass through
			})
		})
		return r
	}

	cases := []struct {
		name string
		path string
		want int
	}{
		{"own organization allowed", "/v1/organizations/" + callerOrganization.String() + "/roles", http.StatusOK},
		{"cross organization forbidden", "/v1/organizations/" + otherOrganization.String() + "/roles", http.StatusForbidden},
		{"malformed organization rejected", "/v1/organizations/not-a-uuid/roles", http.StatusBadRequest},
		{"no organization param passes through", "/v1/users/" + uuid.New().String(), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newRouter().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("%s: got %d, want %d", tc.path, w.Code, tc.want)
			}
		})
	}
}

// TestRequireAuth_AgentStatusEnforced checks that a valid agent token is refused
// with 401 unless AgentStatus reports the agent active, so suspending an agent
// takes effect on its next request rather than at token expiry.
// testIssuer returns an issuer with a fresh signing key, issuing for qeet-test.
func testIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	keyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := tokens.NewIssuer(keyPEM, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

func TestRequireAuth_AgentStatusEnforced(t *testing.T) {
	iss := testIssuer(t)
	organizationID, agentID := uuid.New(), uuid.New()
	now := time.Now()
	// Mint an agent access token the way the agents service does: a normal ES256
	// access token additionally carrying actor_type=agent + agent_id.
	agentTok, err := iss.Sign(jwt.MapClaims{
		"iss":             "qeet-test",
		"aud":             "qeet-test",
		"sub":             agentID.String(),
		"iat":             now.Unix(),
		"nbf":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jti":             uuid.NewString(),
		"organization_id": organizationID.String(),
		"scope":           "openid",
		"actor_type":      "agent",
		"agent_id":        agentID.String(),
	})
	if err != nil {
		t.Fatalf("sign agent token: %v", err)
	}

	cases := []struct {
		name        string
		status      string
		statusErr   error
		wantCode    int
		wantReached bool
	}{
		{"active agent passes", "active", nil, http.StatusOK, true},
		{"suspended agent denied", "suspended", nil, http.StatusUnauthorized, false},
		{"decommissioned agent denied", "decommissioned", nil, http.StatusUnauthorized, false},
		{"unknown agent denied", "", errors.New("not found"), http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			v := liveVerifier(httpx.AuthVerifier{
				Tokens: iss,
				AgentStatus: func(_ context.Context, id uuid.UUID) (string, error) {
					if id != agentID {
						t.Fatalf("AgentStatus called with %s, want %s", id, agentID)
					}
					return tc.status, tc.statusErr
				},
			})
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if p := httpx.PrincipalFromCtx(r.Context()); p == nil || p.ActorType != "agent" {
					t.Errorf("handler principal = %+v, want actor_type=agent", p)
				}
				w.WriteHeader(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer "+agentTok)
			httpx.RequireAuth(v)(next).ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if reached != tc.wantReached {
				t.Fatalf("handler reached = %v, want %v", reached, tc.wantReached)
			}
		})
	}
}

// TestRequireAuth_EndedSessionRefused checks that a user's own access token is
// refused once its session has ended, that a failed lookup is not a pass, and
// that an application's token, which has no session of its own, isn't looked up.
func TestRequireAuth_EndedSessionRefused(t *testing.T) {
	iss := testIssuer(t)
	userID, organizationID, sessionID := uuid.New(), uuid.New(), uuid.New()
	own, _, err := iss.IssueSessionAccess(userID, organizationID, sessionID, nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	app, _, err := iss.IssueClientAccess(tokens.ClientAccess{UserID: userID, OrganizationID: organizationID, SessionID: uuid.New(), ClientID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		token    string
		live     bool
		lookErr  error
		wantCode int
		wantLook bool
	}{
		{"a live session passes", own, true, nil, http.StatusOK, true},
		{"an ended session is refused", own, false, nil, http.StatusUnauthorized, true},
		{"a failed lookup is not a pass", own, true, errors.New("db down"), http.StatusInternalServerError, true},
		{"an application's token isn't looked up", app, false, nil, http.StatusOK, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			looked := false
			v := liveVerifier(httpx.AuthVerifier{
				Tokens: iss,
				SessionLive: func(_ context.Context, sid, uid uuid.UUID) (bool, error) {
					looked = true
					if sid != sessionID || uid != userID {
						t.Errorf("SessionLive(%s, %s), want (%s, %s)", sid, uid, sessionID, userID)
					}
					return tc.live, tc.lookErr
				},
			})
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			httpx.RequireAuth(v)(next).ServeHTTP(w, req)
			if w.Code != tc.wantCode || looked != tc.wantLook {
				t.Fatalf("status %d, looked up %v; want %d, %v (body: %s)", w.Code, looked, tc.wantCode, tc.wantLook, w.Body.String())
			}
		})
	}
}

func TestRequireOrganization(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"organization present", &httpx.Principal{UserID: &uid, OrganizationID: &tid}, tid, false},
		{"organization-less principal", &httpx.Principal{UserID: &uid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireOrganization(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got organization %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}

func TestRequireUser(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"user present", &httpx.Principal{UserID: &uid, OrganizationID: &tid}, uid, false},
		{"user-less principal", &httpx.Principal{OrganizationID: &tid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireUser(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got user %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}

// TestRequireAuth_PrincipalLiveEnforced checks that a service principal's
// valid token is refused once PrincipalLive reports it disabled or gone, so
// disabling one takes effect on its next request.
func TestRequireAuth_PrincipalLiveEnforced(t *testing.T) {
	iss := testIssuer(t)
	principalID := uuid.New()
	now := time.Now()
	tok, err := iss.Sign(jwt.MapClaims{
		"iss": "qeet-test", "aud": "qeet-test", "sub": principalID.String(),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": uuid.NewString(),
		"organization_id": uuid.NewString(), "scope": "users.read", "actor_type": "service",
	})
	if err != nil {
		t.Fatalf("sign service token: %v", err)
	}
	for _, tc := range []struct {
		name string
		live bool
		err  error
		want int
	}{
		{"a live principal passes", true, nil, http.StatusOK},
		{"a disabled or deleted principal is refused", false, nil, http.StatusUnauthorized},
		{"a failed lookup refuses", false, errors.New("db down"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := liveVerifier(httpx.AuthVerifier{Tokens: iss, PrincipalLive: func(_ context.Context, id uuid.UUID) (bool, error) {
				if id != principalID {
					t.Fatalf("PrincipalLive called with %s, want %s", id, principalID)
				}
				return tc.live, tc.err
			}})
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			httpx.RequireAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestLiveFollowsWhatAdmitted checks that a principal admitted earlier stays
// live only as long as what admitted it: its token unexpired, its API key, service
// principal, agent and own session still in force, and that a check that
// fails answers no with its error.
func TestLiveFollowsWhatAdmitted(t *testing.T) {
	ctx := context.Background()
	organization, user, session, agent, key := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	down := errors.New("down")
	soon, gone := time.Now().Add(time.Hour), time.Now().Add(-time.Second)
	answer := func(live bool, err error) func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		return func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return live, err }
	}
	principalAnswer := func(live bool) func(context.Context, uuid.UUID) (bool, error) {
		return func(context.Context, uuid.UUID) (bool, error) { return live, nil }
	}
	agentAnswer := func(status string, err error) func(context.Context, uuid.UUID) (string, error) {
		return func(context.Context, uuid.UUID) (string, error) { return status, err }
	}
	person := &httpx.Principal{ActorType: "user", UserID: &user, OrganizationID: &organization, SessionID: &session, ExpiresAt: &soon}
	apiKey := &httpx.Principal{ActorType: "api_key", Subject: key.String(), OrganizationID: &organization}
	for _, c := range []struct {
		name    string
		v       httpx.AuthVerifier
		p       *httpx.Principal
		want    bool
		wantErr error
	}{
		{"no principal", allLive(httpx.AuthVerifier{}), nil, false, nil},
		{"an expired token", allLive(httpx.AuthVerifier{SessionLive: answer(true, nil)}),
			&httpx.Principal{ActorType: "user", UserID: &user, SessionID: &session, ExpiresAt: &gone}, false, nil},
		{"a person's live session", allLive(httpx.AuthVerifier{SessionLive: answer(true, nil)}), person, true, nil},
		{"a person's ended session", allLive(httpx.AuthVerifier{SessionLive: answer(false, nil)}), person, false, nil},
		{"a session that can't be read", allLive(httpx.AuthVerifier{SessionLive: answer(true, down)}), person, false, down},
		{"an application's token is not the person's session", allLive(httpx.AuthVerifier{SessionLive: answer(false, nil)}),
			&httpx.Principal{ActorType: "user", UserID: &user, SessionID: &session, ClientID: "app"}, true, nil},
		{"a live API key", allLive(httpx.AuthVerifier{APIKeyLive: answer(true, nil)}), apiKey, true, nil},
		{"a revoked API key", allLive(httpx.AuthVerifier{APIKeyLive: answer(false, nil)}), apiKey, false, nil},
		{"an API key that can't be read", allLive(httpx.AuthVerifier{APIKeyLive: answer(true, down)}), apiKey, false, down},
		{"an API key naming no organization", allLive(httpx.AuthVerifier{APIKeyLive: answer(true, nil)}),
			&httpx.Principal{ActorType: "api_key", Subject: key.String()}, false, nil},
		{"an API key whose subject isn't an id", allLive(httpx.AuthVerifier{APIKeyLive: answer(true, nil)}),
			&httpx.Principal{ActorType: "api_key", Subject: "qk_x", OrganizationID: &organization}, false, nil},
		{"an enabled service principal", allLive(httpx.AuthVerifier{PrincipalLive: principalAnswer(true)}),
			&httpx.Principal{ActorType: "service", Subject: key.String()}, true, nil},
		{"a disabled service principal", allLive(httpx.AuthVerifier{PrincipalLive: principalAnswer(false)}),
			&httpx.Principal{ActorType: "service", Subject: key.String()}, false, nil},
		{"an active agent", allLive(httpx.AuthVerifier{AgentStatus: agentAnswer("active", nil)}),
			&httpx.Principal{ActorType: "agent", AgentID: &agent}, true, nil},
		{"a suspended agent", allLive(httpx.AuthVerifier{AgentStatus: agentAnswer("suspended", nil)}),
			&httpx.Principal{ActorType: "agent", AgentID: &agent}, false, nil},
	} {
		got, err := c.v.Live(ctx, c.p)
		if got != c.want || !errors.Is(err, c.wantErr) {
			t.Errorf("%s: %v, %v; want %v, %v", c.name, got, err, c.want, c.wantErr)
		}
	}
}

// serveAuth runs req through RequireAuth(v) and returns the response and the
// principal the next handler saw (nil when it wasn't reached).
func serveAuth(v *httpx.AuthVerifier, req *http.Request) (*httptest.ResponseRecorder, *httpx.Principal) {
	var seen *httpx.Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = httpx.PrincipalFromCtx(r.Context())
		if seen == nil {
			seen = &httpx.Principal{}
		}
		w.WriteHeader(http.StatusOK)
	})
	w := httptest.NewRecorder()
	httpx.RequireAuth(v)(next).ServeHTTP(w, req)
	return w, seen
}

// TestRequireAuth_AdmitsAndRefusesAsItAlwaysHas pins which requests
// RequireAuth admits, with what principal, and how it refuses the rest: an
// earlier principal passes as it is; development headers count only when
// trusted; a missing or bad bearer token is a 401 naming the realm; a user's
// own session token carries its user, organization, session, scopes and
// expiry and is reported used, while an application's token is not.
func TestRequireAuth_AdmitsAndRefusesAsItAlwaysHas(t *testing.T) {
	iss := testIssuer(t)
	userID, organizationID, sessionID := uuid.New(), uuid.New(), uuid.New()
	get := func(header ...string) *http.Request {
		req := httptest.NewRequest("GET", "/v1/anything", nil)
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		return req
	}

	earlier := &httpx.Principal{ActorType: "api_key", Subject: "qk_1"}
	req := get()
	req = req.WithContext(httpx.WithPrincipal(req.Context(), earlier))
	if w, p := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss}), req); w.Code != http.StatusOK || p != earlier {
		t.Errorf("an earlier principal: %d %+v, want it passed on as it is", w.Code, p)
	}

	dev := get("X-Dev-User", userID.String(), "X-Dev-Organization", organizationID.String())
	if w, _ := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss}), dev); w.Code != http.StatusUnauthorized {
		t.Errorf("development headers untrusted: %d, want 401", w.Code)
	}
	w, p := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss, DevTrustHeaders: true}), dev)
	if w.Code != http.StatusOK || p.ActorType != "user" || p.Subject != userID.String() || *p.UserID != userID || *p.OrganizationID != organizationID {
		t.Errorf("development headers trusted: %d %+v", w.Code, p)
	}
	if w, p := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss, DevTrustHeaders: true}), get("X-Dev-User", "someone", "X-Dev-Organization", "not-a-uuid")); w.Code != http.StatusOK || p.Subject != "someone" || p.UserID != nil || p.OrganizationID != nil {
		t.Errorf("development headers that aren't ids: %d %+v", w.Code, p)
	}

	for name, c := range map[string]struct {
		header, challenge string
	}{
		"no token":       {"", `Bearer realm="qeet"`},
		"another scheme": {"Basic dXNlcjpwYXNz", `Bearer realm="qeet"`},
		"a bad token":    {"Bearer not-a-jwt", `Bearer realm="qeet", error="invalid_token"`},
	} {
		w, p := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss}), get("Authorization", c.header))
		if w.Code != http.StatusUnauthorized || p != nil || w.Header().Get("WWW-Authenticate") != c.challenge {
			t.Errorf("%s: %d %q, want 401 %q", name, w.Code, w.Header().Get("WWW-Authenticate"), c.challenge)
		}
	}

	own, exp, err := iss.IssueAccess(userID, organizationID, sessionID, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	var used []uuid.UUID
	v := liveVerifier(httpx.AuthVerifier{Tokens: iss, SessionUsed: func(_ context.Context, sid uuid.UUID) { used = append(used, sid) }})
	w, p = serveAuth(v, get("Authorization", "bearer "+own))
	if w.Code != http.StatusOK || p.ActorType != "user" || p.Subject != userID.String() || *p.UserID != userID ||
		*p.OrganizationID != organizationID || *p.SessionID != sessionID || p.ClientID != "" || p.AgentID != nil ||
		len(p.Scopes) != 2 || p.Scopes[0] != "openid" || p.Scopes[1] != "profile" || p.ExpiresAt == nil || !p.ExpiresAt.Equal(exp.Truncate(time.Second)) {
		t.Errorf("a user's own token: %d %+v", w.Code, p)
	}
	if len(used) != 1 || used[0] != sessionID {
		t.Errorf("sessions reported used: %v, want the token's own", used)
	}

	app, _, err := iss.IssueClientAccess(tokens.ClientAccess{UserID: userID, OrganizationID: organizationID, SessionID: sessionID, ClientID: "app", Scopes: "openid"})
	if err != nil {
		t.Fatal(err)
	}
	used = nil
	if w, p := serveAuth(v, get("Authorization", "Bearer "+app)); w.Code != http.StatusOK || p.ClientID != "app" || len(used) != 0 {
		t.Errorf("an application's token: %d %+v, used %v; want admitted, its client named, no session use", w.Code, p, used)
	}

	agentID := uuid.New()
	machine, err := iss.IssueMachineAccess(tokens.MachineAccess{Subject: agentID, OrganizationID: organizationID, Scopes: []string{"users.read"}, Agent: true})
	if err != nil {
		t.Fatal(err)
	}
	if w, p := serveAuth(liveVerifier(httpx.AuthVerifier{Tokens: iss}), get("Authorization", "Bearer "+machine.AccessToken)); w.Code != http.StatusOK || p.ActorType != "agent" || p.AgentID == nil || *p.AgentID != agentID || p.UserID != nil {
		t.Errorf("an agent's token with no status check: %d %+v", w.Code, p)
	}
}

// allLive is v with each liveness check it leaves unset passing everything,
// so a test sets only the check it is about.
func allLive(v httpx.AuthVerifier) httpx.AuthVerifier {
	if v.AgentStatus == nil {
		v.AgentStatus = func(context.Context, uuid.UUID) (string, error) { return "active", nil }
	}
	if v.SessionUsed == nil {
		v.SessionUsed = func(context.Context, uuid.UUID) {}
	}
	if v.SessionLive == nil {
		v.SessionLive = func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil }
	}
	if v.PrincipalLive == nil {
		v.PrincipalLive = func(context.Context, uuid.UUID) (bool, error) { return true, nil }
	}
	if v.APIKeyLive == nil {
		v.APIKeyLive = func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil }
	}
	return v
}

// liveVerifier is allLive(v), as RequireAuth takes it.
func liveVerifier(v httpx.AuthVerifier) *httpx.AuthVerifier {
	v = allLive(v)
	return &v
}

// TestNewAuthVerifierNeedsEveryCheck checks that the request verifier is not
// built without its issuer or any of the liveness checks that refuse at once
// the tokens of an ended session, a disabled principal or key, or a suspended
// agent.
func TestNewAuthVerifierNeedsEveryCheck(t *testing.T) {
	full := allLive(httpx.AuthVerifier{Tokens: testIssuer(t)})
	if _, err := httpx.NewAuthVerifier(full); err != nil {
		t.Fatalf("built with every check: %v", err)
	}
	for name, without := range map[string]func(*httpx.AuthVerifier){
		"issuer":         func(v *httpx.AuthVerifier) { v.Tokens = nil },
		"agent status":   func(v *httpx.AuthVerifier) { v.AgentStatus = nil },
		"session use":    func(v *httpx.AuthVerifier) { v.SessionUsed = nil },
		"session live":   func(v *httpx.AuthVerifier) { v.SessionLive = nil },
		"principal live": func(v *httpx.AuthVerifier) { v.PrincipalLive = nil },
		"API key live":   func(v *httpx.AuthVerifier) { v.APIKeyLive = nil },
	} {
		v := full
		without(&v)
		if _, err := httpx.NewAuthVerifier(v); err == nil {
			t.Errorf("built without the %s check", name)
		}
	}
}
