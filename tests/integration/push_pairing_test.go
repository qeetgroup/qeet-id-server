//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// A phone is linked with a one-time pairing code instead of a copied access
// token: the signed-in person asks for one (after a step-up when they hold a
// factor), the phone exchanges it once, and the screen showing it sees the
// link. Wrong, used, replaced, withdrawn and expired codes are all refused
// alike, and asking and guessing are both limited.

var pairingCodeShape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$`)

type pairingFixture struct {
	svc      *mfa.Service
	router   http.Handler
	userID   uuid.UUID
	tenantID uuid.UUID
	session  uuid.UUID
}

// newPairingFixture mounts the pairing routes as production does: the phone's
// claim public, the person's routes behind their session and the step-up gate.
func newPairingFixture(t *testing.T, ctx context.Context, throttle func(http.Handler) http.Handler) *pairingFixture {
	t.Helper()
	f := &pairingFixture{svc: newStepUpMFA(t)}
	f.tenantID = createTenant(t, ctx, uniqueSlug("pairing"))
	f.userID = createUserInTenant(t, ctx, f.tenantID)
	f.session = openSession(t, ctx, f.userID, f.tenantID)
	h := &mfa.Handler{Service: f.svc, PairingThrottle: throttle}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) { h.MountPublic(r) })
		r.Group(func(r chi.Router) {
			r.Use(withSessionPrincipal(f.userID, f.tenantID, f.session))
			r.Use(f.svc.StepUpGate(map[string]mfa.StepUpRule{"POST /v1/mfa/push/pairing": mfa.StepUpWhenFactorHeld}))
			h.Mount(r)
		})
	})
	f.router = r
	return f
}

func (f *pairingFixture) call(method, path string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.20:4000"
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

type issuedPairing struct {
	ID     uuid.UUID `json:"id"`
	Code   string    `json:"code"`
	Status string    `json:"status"`
}

func (f *pairingFixture) ask(t *testing.T) issuedPairing {
	t.Helper()
	rr := f.call(http.MethodPost, "/v1/mfa/push/pairing", nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("ask for a pairing code: %d %s", rr.Code, rr.Body.String())
	}
	var p issuedPairing
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	return p
}

func (f *pairingFixture) claim(code string) *httptest.ResponseRecorder {
	return f.call(http.MethodPost, "/v1/mfa/push/pairing/claim", map[string]string{
		"code": code, "name": "Phone", "push_token": "ExponentPushToken[" + uniqueSlug("tok") + "]", "platform": "ios"})
}

func (f *pairingFixture) status(t *testing.T, id uuid.UUID) mfa.PushPairing {
	t.Helper()
	rr := f.call(http.MethodGet, "/v1/mfa/push/pairing/"+id.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("pairing status: %d %s", rr.Code, rr.Body.String())
	}
	var p mfa.PushPairing
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	return p
}

func refusedAsInvalid(t *testing.T, rr *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rr.Code != http.StatusUnauthorized || errorCode(t, rr) != errs.CodeMFAPairingCodeInvalid {
		t.Fatalf("%s must be refused as an invalid pairing code: %d %s", what, rr.Code, rr.Body.String())
	}
}

// TestPhoneLinksWithAPairingCode: once the person holding a factor steps up,
// they get a code; the phone links with it as typed in any case, gets its
// device credential and can answer approval requests; the code shows as
// linked and works only once. Both steps are audited.
func TestPhoneLinksWithAPairingCode(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newPairingFixture(t, ctx, nil)
	holdApp(t, ctx, f.svc, f.userID)
	if rr := f.call(http.MethodPost, "/v1/mfa/push/pairing", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("asking for a code while holding a factor needs a step-up: %d %s", rr.Code, rr.Body.String())
	}
	recordStepUp(t, ctx, f.svc, f.userID, f.session, "totp")

	p := f.ask(t)
	if !pairingCodeShape.MatchString(p.Code) || p.Status != "pending" {
		t.Fatalf("a pending code grouped for reading: %+v", p)
	}
	typed := strings.ToLower(strings.ReplaceAll(p.Code, "-", " "))
	rr := f.claim(typed)
	if rr.Code != http.StatusCreated {
		t.Fatalf("the phone links with the code as typed: %d %s", rr.Code, rr.Body.String())
	}
	var linked mfa.PushPairingClaim
	_ = json.Unmarshal(rr.Body.Bytes(), &linked)
	if linked.UserID != f.userID || linked.DeviceToken == "" || linked.Device.ID == uuid.Nil {
		t.Fatalf("the phone must get the account, its device and its credential: %+v", linked)
	}
	if got := f.status(t, p.ID); got.Status != "linked" || got.DeviceID == nil || *got.DeviceID != linked.Device.ID {
		t.Fatalf("the screen must see the code linked the phone: %+v", got)
	}
	challenge, err := f.svc.CreatePushChallenge(ctx, f.userID, "sign_in", mfa.PushChallengeContext{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RespondToPushChallenge(ctx, challenge, f.userID, linked.DeviceToken, true); err != nil {
		t.Fatalf("the linked phone must answer approval requests: %v", err)
	}
	refusedAsInvalid(t, f.claim(p.Code), "a code used a second time")
	if n := pushDevicesLeft(t, ctx, f.userID); n != 1 {
		t.Fatalf("one code links one phone, %d linked", n)
	}
	if deviceAuditCount(t, ctx, f.userID, "mfa.push_pairing_created") != 1 ||
		deviceAuditCount(t, ctx, f.userID, "mfa.push_device_linked") != 1 {
		t.Error("asking for the code and linking with it must both be audited")
	}
}

// TestPairingCodesStopWorking: a newer code replaces an older one; a withdrawn
// or expired code is refused like a wrong one; another person's code cannot
// be seen or withdrawn.
func TestPairingCodesStopWorking(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newPairingFixture(t, ctx, nil)

	refusedAsInvalid(t, f.claim("ABCDE-FGHJK"), "a wrong code")
	refusedAsInvalid(t, f.claim("not a code"), "something that cannot be a code")

	older, newer := f.ask(t), f.ask(t)
	refusedAsInvalid(t, f.claim(older.Code), "a code replaced by a newer one")
	if got := f.status(t, older.ID); got.Status != "expired" {
		t.Fatalf("a replaced code reads as expired: %+v", got)
	}

	if rr := f.call(http.MethodDelete, "/v1/mfa/push/pairing/"+newer.ID.String(), nil); rr.Code != http.StatusNoContent {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	refusedAsInvalid(t, f.claim(newer.Code), "a withdrawn code")

	late := f.ask(t)
	if _, err := testPool.Exec(ctx, `UPDATE auth.mfa_push_pairings SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, late.ID); err != nil {
		t.Fatal(err)
	}
	refusedAsInvalid(t, f.claim(late.Code), "an expired code")

	other := newPairingFixture(t, ctx, nil)
	theirs := other.ask(t)
	if rr := f.call(http.MethodGet, "/v1/mfa/push/pairing/"+theirs.ID.String(), nil); rr.Code != http.StatusNotFound {
		t.Fatalf("another person's code must not be found: %d", rr.Code)
	}
	if rr := f.call(http.MethodDelete, "/v1/mfa/push/pairing/"+theirs.ID.String(), nil); rr.Code != http.StatusNotFound {
		t.Fatalf("another person's code must not be withdrawn: %d", rr.Code)
	}
	if rr := other.claim(theirs.Code); rr.Code != http.StatusCreated {
		t.Fatalf("their code still works: %d %s", rr.Code, rr.Body.String())
	}
}

// TestPairingIsLimited: a person may ask for ten codes an hour; guesses at a
// code are slowed per address; a suspended account's code links nothing.
func TestPairingIsLimited(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newPairingFixture(t, ctx, ratelimit.New(0.01, 3).MiddlewareBy("pairing", ratelimit.PerIP))

	for range 10 {
		f.ask(t)
	}
	rr := f.call(http.MethodPost, "/v1/mfa/push/pairing", nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("an eleventh code in an hour must be refused: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if wait, _ := body.Error.Metadata["retry_after"].(float64); wait < 1 {
		t.Fatalf("the refusal must say when to ask again: %s", rr.Body.String())
	}

	for i := range 3 {
		refusedAsInvalid(t, f.claim("ABCDE-FGHJK"), "guess "+string(rune('1'+i)))
	}
	if rr := f.claim("ABCDE-FGHJK"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("further guesses from the address must be slowed: %d %s", rr.Code, rr.Body.String())
	}

	s := newPairingFixture(t, ctx, nil)
	p := s.ask(t)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, s.userID); err != nil {
		t.Fatal(err)
	}
	refusedAsInvalid(t, s.claim(p.Code), "a code for a suspended account")
}
