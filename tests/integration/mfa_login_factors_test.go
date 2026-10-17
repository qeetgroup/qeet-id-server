//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Any confirmed second factor a person holds — not only an authenticator app —
// makes password sign-in return a challenge listing exactly their factors, and
// the challenge can be met by any of them: an emailed or texted code, a passkey
// assertion, or an approved push.

const factorPassword = "Kx7mQ2vLp9Wz"

type factorFixture struct {
	auth     *auth.Service
	mfa      *mfa.Service
	passkeys *passkey.Service
	sender   *captureSender
	router   http.Handler
	tenantID uuid.UUID
}

func newFactorFixture(t *testing.T, ctx context.Context) *factorFixture {
	t.Helper()
	f := &factorFixture{sender: &captureSender{}, tenantID: createTenant(t, ctx, uniqueSlug("factors"))}
	f.auth, _ = newAuth()
	f.mfa = mfa.NewService(testPool, "qeet", f.sender, "")
	f.mfa.SetCipher(testEnvelope(t))
	f.passkeys = newPasskeySvcWithAuth(t, f.auth)
	f.mfa.SetWebAuthn(f.passkeys)
	f.auth.SetMFA(f.mfa)
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		(&auth.Handler{Service: f.auth, Validate: validator.New()}).Mount(r)
	})
	f.router = r
	return f
}

// member creates a password account in the fixture's organisation.
func (f *factorFixture) member(t *testing.T, ctx context.Context) (uuid.UUID, string) {
	t.Helper()
	email := uniqueSlug("factor") + "@example.com"
	id := createTenantUser(t, ctx, f.tenantID, email)
	hash, err := password.Hash(factorPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash`, id, hash); err != nil {
		t.Fatal(err)
	}
	return id, email
}

func (f *factorFixture) post(path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

type challenge struct {
	MFARequired bool               `json:"mfa_required"`
	MFAToken    string             `json:"mfa_token"`
	Methods     []string           `json:"methods"`
	Factors     []auth.LoginFactor `json:"factors"`
	AccessToken string             `json:"access_token"`
}

func (f *factorFixture) signIn(t *testing.T, email string) challenge {
	t.Helper()
	rr := f.post("/v1/auth/login", map[string]string{"email": email, "password": factorPassword})
	if rr.Code != http.StatusOK {
		t.Fatalf("sign in: %d %s", rr.Code, rr.Body.String())
	}
	var c challenge
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	return c
}

func (f *factorFixture) complete(body map[string]any) (*httptest.ResponseRecorder, challenge) {
	rr := f.post("/v1/auth/mfa", body)
	var c challenge
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	return rr, c
}

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)

// TestEmailCodeIsASecondFactor: a person whose only second factor is an email
// code factor is challenged, offered exactly that factor, and signs in with a
// code sent to it.
func TestEmailCodeIsASecondFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	me, email := f.member(t, ctx)
	var factorID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at)
		VALUES ($1, 'email', $2, NOW()) RETURNING id`, me, email).Scan(&factorID); err != nil {
		t.Fatal(err)
	}

	c := f.signIn(t, email)
	if !c.MFARequired || c.AccessToken != "" {
		t.Fatalf("sign-in with an email factor was not challenged: %+v", c)
	}
	if len(c.Factors) != 1 || c.Factors[0].Type != "email" || c.Factors[0].ID == nil || *c.Factors[0].ID != factorID ||
		c.Factors[0].Destination == email || len(c.Methods) != 1 || c.Methods[0] != "email" {
		t.Fatalf("challenge offered %+v / %v, want exactly the masked email factor", c.Factors, c.Methods)
	}

	if rr := f.post("/v1/auth/mfa/send", map[string]any{"mfa_token": c.MFAToken, "factor_id": factorID}); rr.Code != http.StatusOK {
		t.Fatalf("send code: %d %s", rr.Code, rr.Body.String())
	}
	m, ok := f.sender.last()
	code := sixDigits.FindStringSubmatch(m.Body)
	if !ok || m.To != email || code == nil {
		t.Fatalf("no code was sent to the factor: %+v", m)
	}
	if rr, _ := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": "000000"}); errorCode(t, rr) != errs.CodeMFACodeInvalid {
		t.Errorf("a wrong code: %d %s", rr.Code, rr.Body.String())
	}
	rr, done := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": code[1]})
	if rr.Code != http.StatusOK || done.AccessToken == "" {
		t.Fatalf("complete with the emailed code: %d %s", rr.Code, rr.Body.String())
	}
}

// TestPasskeyIsASecondFactor: a person whose only second factor is a passkey
// is challenged, offered it, and signs in with an assertion from the ceremony
// begun for the challenge — not from another.
func TestPasskeyIsASecondFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	me, email := f.member(t, ctx)
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	a := virtualwebauthn.NewAuthenticator()
	c := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	sid, creation, err := f.passkeys.BeginRegister(ctx, me)
	if err != nil {
		t.Fatal(err)
	}
	cj, _ := json.Marshal(creation)
	copts, err := virtualwebauthn.ParseAttestationOptions(string(cj))
	if err != nil {
		t.Fatal(err)
	}
	a.Options.UserHandle = []byte(copts.UserID)
	if err := f.passkeys.FinishRegister(ctx, me, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, a, c, *copts)), "", "test"); err != nil {
		t.Fatalf("register passkey: %v", err)
	}
	a.AddCredential(c)

	ch := f.signIn(t, email)
	if !ch.MFARequired || len(ch.Factors) != 1 || ch.Factors[0].Type != "passkey" {
		t.Fatalf("challenge offered %+v, want exactly the passkey", ch)
	}
	rr := f.post("/v1/auth/mfa/passkey/begin", map[string]string{"mfa_token": ch.MFAToken})
	if rr.Code != http.StatusOK {
		t.Fatalf("begin passkey: %d %s", rr.Code, rr.Body.String())
	}
	var begin struct {
		SessionID uuid.UUID       `json:"session_id"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &begin)
	aopts, err := virtualwebauthn.ParseAssertionOptions(`{"publicKey":` + string(begin.PublicKey) + `}`)
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	assertion := json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, a, c, *aopts))

	if rr, _ := f.complete(map[string]any{"mfa_token": ch.MFAToken, "passkey": map[string]any{"session_id": uuid.New(), "credential": assertion}}); rr.Code == http.StatusOK {
		t.Fatal("an assertion for another ceremony met the challenge")
	}
	rr, done := f.complete(map[string]any{"mfa_token": ch.MFAToken, "passkey": map[string]any{"session_id": begin.SessionID, "credential": assertion}})
	if rr.Code != http.StatusOK || done.AccessToken == "" {
		t.Fatalf("complete with the passkey: %d %s", rr.Code, rr.Body.String())
	}
}

// TestPushApprovalIsASecondFactor: a person whose only second factor is a push
// device is challenged and offered it; completing waits while the request is
// unanswered (without costing an attempt), succeeds once it is approved, and
// cannot be repeated.
func TestPushApprovalIsASecondFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	me, email := f.member(t, ctx)
	_, deviceToken, err := f.mfa.RegisterPushDevice(ctx, me, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios")
	if err != nil {
		t.Fatalf("register push device: %v", err)
	}

	ch := f.signIn(t, email)
	if !ch.MFARequired || len(ch.Factors) != 1 || ch.Factors[0].Type != "push" {
		t.Fatalf("challenge offered %+v, want exactly the push device", ch)
	}
	if rr, _ := f.complete(map[string]any{"mfa_token": ch.MFAToken, "push": true}); rr.Code == http.StatusOK {
		t.Fatal("push completed before any request was sent")
	}
	if rr := f.post("/v1/auth/mfa/push", map[string]string{"mfa_token": ch.MFAToken}); rr.Code != http.StatusOK {
		t.Fatalf("send push: %d %s", rr.Code, rr.Body.String())
	}
	for i := 0; i < 6; i++ { // more than the attempt budget: waiting costs nothing
		if rr, _ := f.complete(map[string]any{"mfa_token": ch.MFAToken, "push": true}); errorCode(t, rr) != errs.CodeMFAPushPending {
			t.Fatalf("poll %d before approval: %d %s", i+1, rr.Code, rr.Body.String())
		}
	}
	var pushID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT push_challenge_id FROM auth.mfa_login_challenges WHERE id = $1`, ch.MFAToken).Scan(&pushID); err != nil {
		t.Fatal(err)
	}
	if err := f.mfa.RespondToPushChallenge(ctx, pushID, me, deviceToken, true); err != nil {
		t.Fatalf("approve: %v", err)
	}
	rr, done := f.complete(map[string]any{"mfa_token": ch.MFAToken, "push": true})
	if rr.Code != http.StatusOK || done.AccessToken == "" {
		t.Fatalf("complete after approval: %d %s", rr.Code, rr.Body.String())
	}
	if rr, _ := f.complete(map[string]any{"mfa_token": ch.MFAToken, "push": true}); rr.Code == http.StatusOK {
		t.Fatal("the same approval signed in twice")
	}
}

// TestChallengeListsExactlyTheFactorsHeld covers: the advertised factors are
// those the person holds (authenticator app with recovery codes, plus an SMS
// factor), in both sign-in flows; a person with no confirmed factor signs in
// without a challenge, as before; an unconfirmed factor does not count.
func TestChallengeListsExactlyTheFactorsHeld(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)

	none, noneEmail := f.member(t, ctx)
	if _, err := testPool.Exec(ctx, `INSERT INTO auth.mfa_otp_factors (user_id, channel, destination) VALUES ($1, 'sms', '+919999999999')`, none); err != nil {
		t.Fatal(err)
	}
	if c := f.signIn(t, noneEmail); c.MFARequired || c.AccessToken == "" {
		t.Fatalf("a person with only an unconfirmed factor was challenged: %+v", c)
	}

	me, email := f.member(t, ctx)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := f.mfa.StartEnroll(ctx, tx, me, email)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := mfaConfirmEnroll(ctx, f.mfa, me, totpCodeAtStep(t, enr.Secret, 0)); err != nil {
		t.Fatalf("confirm authenticator: %v", err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at) VALUES ($1, 'sms', '+919999999998', NOW())`, me); err != nil {
		t.Fatal(err)
	}
	want := []string{"totp", "recovery_code", "sms"}
	c := f.signIn(t, email)
	if len(c.Methods) != len(want) {
		t.Fatalf("token flow offered %v, want %v", c.Methods, want)
	}
	for i := range want {
		if c.Methods[i] != want[i] {
			t.Fatalf("token flow offered %v, want %v", c.Methods, want)
		}
	}
	res, err := f.auth.BeginLoginSession(ctx, auth.SignInAttempt{Email: email, Password: factorPassword}, "test", "", "")
	if err != nil || !res.MFARequired || len(res.Methods) != len(want) {
		t.Fatalf("hosted flow: %+v %v, want a challenge offering %v", res, err, want)
	}
}
