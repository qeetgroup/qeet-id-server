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
	"github.com/google/uuid"

	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
)

// User agents a browser sends; the default passkey name is derived from them.
const (
	uaChromeMac    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	uaSafariIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)

// passkeyAPI mounts the signed-in passkey routes the way the authenticated
// router does, as userID (withPrincipal stands in for RequireAuth).
func passkeyAPI(svc *passkey.Service, userID, tenantID uuid.UUID) http.Handler {
	r := chi.NewRouter()
	r.Use(withPrincipal(userID, tenantID))
	(&passkey.Handler{Service: svc}).Mount(r)
	return r
}

func callPasskeyAPI(t *testing.T, h http.Handler, method, path string, body any, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// seedPasskey stores a credential row for userID (nil name = enrolled without
// one) and returns its id.
func seedPasskey(t *testing.T, ctx context.Context, userID uuid.UUID, name *string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, transports, name)
		VALUES ($1, $2, $3, 0, $4, $5) RETURNING id
	`, userID, []byte(uuid.NewString()), []byte("fake-public-key"), []string{"internal"}, name).Scan(&id); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
	return id
}

func storedPasskeyName(t *testing.T, ctx context.Context, id uuid.UUID) *string {
	t.Helper()
	var name *string
	if err := testPool.QueryRow(ctx, `SELECT name FROM auth.passkey_credentials WHERE id = $1`, id).Scan(&name); err != nil {
		t.Fatalf("read passkey name: %v", err)
	}
	return name
}

func strPtr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// listedPasskeyNames returns GET /passkeys as id → name.
func listedPasskeyNames(t *testing.T, h http.Handler) map[uuid.UUID]string {
	t.Helper()
	rr := callPasskeyAPI(t, h, http.MethodGet, "/passkeys", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list passkeys: status %d, body %s", rr.Code, rr.Body)
	}
	var out struct {
		Items []struct {
			ID   uuid.UUID `json:"id"`
			Name *string   `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	names := map[uuid.UUID]string{}
	for _, it := range out.Items {
		names[it.ID] = deref(it.Name)
	}
	return names
}

func errorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return body.Error.Code
}

// TestPasskeyRename: a signed-in user renames one of their own passkeys with
// PATCH /v1/passkeys/{id}. One subtest per expected behaviour.
func TestPasskeyRename(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pkname"))
	owner := createUserInTenant(t, ctx, tenantID)
	other := createUserInTenant(t, ctx, tenantID)
	api := passkeyAPI(newPasskeySvc(t), owner, tenantID)

	rename := func(id string, name any) *httptest.ResponseRecorder {
		return callPasskeyAPI(t, api, http.MethodPatch, "/passkeys/"+id, map[string]any{"name": name}, "")
	}

	t.Run("owner renames a passkey and the list shows the new name", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, strPtr("Old name"))
		rr := rename(id.String(), "Work laptop")
		if rr.Code != http.StatusOK {
			t.Fatalf("rename: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		var got struct {
			ID   uuid.UUID `json:"id"`
			Name *string   `json:"name"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || got.ID != id || deref(got.Name) != "Work laptop" {
			t.Fatalf("rename response = %s (err %v), want the renamed passkey", rr.Body, err)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Work laptop" {
			t.Errorf("stored name = %q, want %q", n, "Work laptop")
		}
		if n := listedPasskeyNames(t, api)[id]; n != "Work laptop" {
			t.Errorf("listed name = %q, want %q", n, "Work laptop")
		}
	})

	t.Run("a passkey enrolled without a name can be named", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, nil)
		if rr := rename(id.String(), "Phone"); rr.Code != http.StatusOK {
			t.Fatalf("rename: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Phone" {
			t.Errorf("stored name = %q, want %q", n, "Phone")
		}
	})

	t.Run("empty or whitespace-only names are refused and the name is kept", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, strPtr("Keep me"))
		for _, name := range []any{"", "   ", "\t\n ", nil} {
			rr := rename(id.String(), name)
			if rr.Code != http.StatusUnprocessableEntity || errorCode(t, rr) != "validation_failed" {
				t.Errorf("rename to %q: status %d code %q, want 422 validation_failed", name, rr.Code, errorCode(t, rr))
			}
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Keep me" {
			t.Errorf("stored name = %q, want it kept as %q", n, "Keep me")
		}
	})

	t.Run("a name longer than the maximum is refused", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, strPtr("Keep me"))
		rr := rename(id.String(), strings.Repeat("a", 65))
		if rr.Code != http.StatusUnprocessableEntity || errorCode(t, rr) != "validation_failed" {
			t.Errorf("65-character name: status %d code %q, want 422 validation_failed", rr.Code, errorCode(t, rr))
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Keep me" {
			t.Errorf("stored name = %q, want it kept as %q", n, "Keep me")
		}
		// The limit counts characters, not bytes: 64 two-byte characters fit.
		longest := strings.Repeat("é", 64)
		if rr := rename(id.String(), longest); rr.Code != http.StatusOK {
			t.Errorf("64-character name: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != longest {
			t.Errorf("stored name = %q, want the 64-character name", n)
		}
	})

	t.Run("another user's passkey is refused and left unchanged", func(t *testing.T) {
		// One user in the same organisation, one in another.
		elsewhere := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("pkname")))
		for _, user := range []uuid.UUID{other, elsewhere} {
			theirs := seedPasskey(t, ctx, user, strPtr("Their key"))
			rr := rename(theirs.String(), "Mine now")
			if rr.Code != http.StatusNotFound {
				t.Errorf("rename another user's passkey: status %d, want 404", rr.Code)
			}
			if n := deref(storedPasskeyName(t, ctx, theirs)); n != "Their key" {
				t.Errorf("their stored name = %q, want it unchanged", n)
			}
		}
	})

	t.Run("an unknown passkey id is refused as not found", func(t *testing.T) {
		if rr := rename(uuid.NewString(), "Anything"); rr.Code != http.StatusNotFound {
			t.Errorf("unknown id: status %d, want 404", rr.Code)
		}
		if rr := rename("not-a-uuid", "Anything"); rr.Code != http.StatusBadRequest {
			t.Errorf("malformed id: status %d, want 400", rr.Code)
		}
	})

	t.Run("markup is stored as plain text and control characters are neutralised", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, nil)
		markup := `<img src=x onerror="alert(1)"> & <b>Key</b>`
		if rr := rename(id.String(), markup); rr.Code != http.StatusOK {
			t.Fatalf("markup name: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != markup {
			t.Errorf("stored name = %q, want the markup kept verbatim as text %q", n, markup)
		}
		// NUL, line breaks, tabs and a right-to-left override would break
		// storage, layout, or reorder the text when shown.
		if rr := rename(id.String(), "Work\x00\nlaptop\t\u202e  evil\x7f"); rr.Code != http.StatusOK {
			t.Fatalf("control-character name: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Work laptop evil" {
			t.Errorf("stored name = %q, want %q", n, "Work laptop evil")
		}
		if rr := rename(id.String(), "\x00\u202e\x1b"); rr.Code != http.StatusUnprocessableEntity {
			t.Errorf("name of only control characters: status %d, want 422", rr.Code)
		}
	})

	t.Run("surrounding whitespace is trimmed", func(t *testing.T) {
		id := seedPasskey(t, ctx, owner, nil)
		if rr := rename(id.String(), "  Desk key  "); rr.Code != http.StatusOK {
			t.Fatalf("rename: status %d, want 200; body %s", rr.Code, rr.Body)
		}
		if n := deref(storedPasskeyName(t, ctx, id)); n != "Desk key" {
			t.Errorf("stored name = %q, want %q", n, "Desk key")
		}
	})
}

// registerPasskeyOverHTTP runs the signed-in enrolment ceremony through
// POST /passkeys/register/{begin,finish} with a virtual authenticator, sending
// name (omitted when nil) and userAgent. It returns the finish response.
func registerPasskeyOverHTTP(t *testing.T, api http.Handler, name *string, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	return beginPasskeyRegistration(t, api, userAgent)(name)
}

// beginPasskeyRegistration runs POST /passkeys/register/begin and the virtual
// authenticator, and returns a func that posts the attestation to
// /passkeys/register/finish with a name (omitted when nil).
func beginPasskeyRegistration(t *testing.T, api http.Handler, userAgent string) func(name *string) *httptest.ResponseRecorder {
	t.Helper()
	begin := callPasskeyAPI(t, api, http.MethodPost, "/passkeys/register/begin", nil, userAgent)
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
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options)
	return func(name *string) *httptest.ResponseRecorder {
		body := map[string]any{"session_id": started.SessionID, "credential": json.RawMessage(attestation)}
		if name != nil {
			body["name"] = *name
		}
		return callPasskeyAPI(t, api, http.MethodPost, "/passkeys/register/finish", body, userAgent)
	}
}

// signupPasskey runs a passkey-first sign-up (hosted when inTenant) with the
// given name and user agent and returns the new user's id.
func signupPasskey(t *testing.T, ctx context.Context, svc *passkey.Service, inTenant bool, name, userAgent string) uuid.UUID {
	t.Helper()
	email := uniqueSlug("pkdefault") + "@example.com"
	var (
		sid      uuid.UUID
		optsJSON []byte
	)
	if inTenant {
		tenantID := createTenant(t, ctx, uniqueSlug("pkdefault"))
		id, creation, err := svc.BeginTenantSignup(ctx, tenantID, email, "")
		if err != nil {
			t.Fatalf("begin tenant signup: %v", err)
		}
		sid = id
		optsJSON, _ = json.Marshal(creation)
	} else {
		id, creation, err := svc.BeginSignup(ctx, email, "")
		if err != nil {
			t.Fatalf("begin signup: %v", err)
		}
		sid = id
		optsJSON, _ = json.Marshal(creation)
	}
	options, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	attestation := json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options))
	var userID uuid.UUID
	if inTenant {
		userID, _, err = svc.FinishTenantSignup(ctx, sid, attestation, name, "203.0.113.7", userAgent)
	} else {
		_, userID, err = svc.FinishSignup(ctx, sid, attestation, name, "203.0.113.7", userAgent)
	}
	if err != nil {
		t.Fatalf("finish signup: %v", err)
	}
	return userID
}

func onlyPasskeyName(t *testing.T, ctx context.Context, svc *passkey.Service, userID uuid.UUID) string {
	t.Helper()
	creds, err := svc.List(ctx, userID)
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 passkey, got %d", len(creds))
	}
	return deref(creds[0].Name)
}

// TestPasskeyEnrolmentDefaultName: every new passkey gets a name. Without one
// from the user, it is named after the enrolling browser ("Chrome on macOS"),
// or "Passkey" when the browser can't be told — on every enrolment path, so a
// list never shows a blank entry for a new passkey.
func TestPasskeyEnrolmentDefaultName(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newPasskeySvc(t)

	t.Run("signed-in enrolment without a name is named after the browser", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("pkdefault"))
		userID := createUserInTenant(t, ctx, tenantID)
		api := passkeyAPI(svc, userID, tenantID)
		if rr := registerPasskeyOverHTTP(t, api, nil, uaChromeMac); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish: status %d, body %s", rr.Code, rr.Body)
		}
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "Chrome on macOS" {
			t.Errorf("name = %q, want %q", n, "Chrome on macOS")
		}
	})

	t.Run("signed-in enrolment keeps a supplied name, trimmed", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("pkdefault"))
		userID := createUserInTenant(t, ctx, tenantID)
		api := passkeyAPI(svc, userID, tenantID)
		if rr := registerPasskeyOverHTTP(t, api, strPtr("  YubiKey 5  "), uaChromeMac); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish: status %d, body %s", rr.Code, rr.Body)
		}
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "YubiKey 5" {
			t.Errorf("name = %q, want %q", n, "YubiKey 5")
		}
	})

	t.Run("signed-in enrolment refuses an over-long name and can be finished with a corrected one", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("pkdefault"))
		userID := createUserInTenant(t, ctx, tenantID)
		api := passkeyAPI(svc, userID, tenantID)
		finish := beginPasskeyRegistration(t, api, uaChromeMac)
		if rr := finish(strPtr(strings.Repeat("a", 65))); rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("register finish with a 65-character name: status %d, want 422", rr.Code)
		}
		if creds, _ := svc.List(ctx, userID); len(creds) != 0 {
			t.Fatalf("want no passkey stored after the refusal, got %d", len(creds))
		}
		// The refusal did not use up the ceremony.
		if rr := finish(strPtr("Laptop")); rr.Code != http.StatusNoContent {
			t.Fatalf("register finish with a corrected name: status %d, body %s", rr.Code, rr.Body)
		}
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "Laptop" {
			t.Errorf("name = %q, want %q", n, "Laptop")
		}
	})

	t.Run("console passkey sign-up is named after the browser", func(t *testing.T) {
		userID := signupPasskey(t, ctx, svc, false, "", uaChromeMac)
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "Chrome on macOS" {
			t.Errorf("name = %q, want %q", n, "Chrome on macOS")
		}
	})

	t.Run("hosted passkey sign-up is named after the browser", func(t *testing.T) {
		authSvc, _ := newAuth()
		authSvc.SetRegistrationPolicy(allowSelfRegistration{})
		userID := signupPasskey(t, ctx, newPasskeySvcWithAuth(t, authSvc), true, "", uaSafariIPhone)
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "Safari on iPhone" {
			t.Errorf("name = %q, want %q", n, "Safari on iPhone")
		}
	})

	t.Run("an unrecognised user agent falls back to Passkey", func(t *testing.T) {
		userID := signupPasskey(t, ctx, svc, false, "", "test-agent")
		if n := onlyPasskeyName(t, ctx, svc, userID); n != "Passkey" {
			t.Errorf("name = %q, want %q", n, "Passkey")
		}
	})
}
