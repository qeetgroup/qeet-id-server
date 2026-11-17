//go:build integration

package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newService returns the passkey service for the relying party example.test.
func newService(t *testing.T) *Service {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "example.test", RPDisplayName: "Qeet ID", RPOrigins: []string{"https://example.test"},
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	return NewService(dbtest.Pool(t), wa, nil)
}

// TestBeginLoginAnswersAlike checks that starting a passkey sign-in answers
// the same, in shape, for an account with a passkey, one without, an unknown
// address and no address.
func TestBeginLoginAnswersAlike(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	tenant := dbtest.Tenant(t)
	withPasskey, without := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key) VALUES ($1, $2, $3)
	`, withPasskey.ID, []byte(dbtest.Unique("credential")), []byte("key")); err != nil {
		t.Fatalf("passkey: %v", err)
	}

	shapes := map[string]string{}
	for name, email := range map[string]string{
		"account with a passkey":    withPasskey.Email,
		"account without a passkey": without.Email,
		"unknown address":           dbtest.Unique("nobody") + "@example.test",
		"no address":                "",
	} {
		id, options, err := svc.BeginLogin(ctx, email)
		if err != nil || id == uuid.Nil || options == nil {
			t.Errorf("%s: %v, %v, %v; want a ceremony", name, id, options, err)
			continue
		}
		raw, err := json.Marshal(options.Response)
		if err != nil {
			t.Fatalf("encode options: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode options: %v", err)
		}
		delete(fields, "challenge")
		shape, _ := json.Marshal(fields)
		shapes[name] = string(shape)
	}
	for name, shape := range shapes {
		if shape != shapes["no address"] {
			t.Errorf("%s answers %s, want %s as for no address", name, shape, shapes["no address"])
		}
	}
}

// signUp runs a passkey sign-up for email over srv, as a browser would: begin,
// then answer with a new passkey on a virtual authenticator. It returns each
// step's status and body (no finish when begin is refused).
func signUp(t *testing.T, srv http.Handler, email string) (beginStatus int, begin string, finishStatus int, finish string) {
	t.Helper()
	rec := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/begin", map[string]any{"email": email})
	if rec.Code != http.StatusOK {
		return rec.Code, rec.Body.String(), 0, ""
	}
	var started struct {
		SessionID uuid.UUID       `json:"session_id"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	dbtest.Decode(t, rec, &started)
	options, err := virtualwebauthn.ParseAttestationOptions(`{"publicKey":` + string(started.PublicKey) + `}`)
	if err != nil {
		t.Fatalf("sign-up options: %v", err)
	}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(options.UserID)})
	response := virtualwebauthn.CreateAttestationResponse(testRP, authenticator, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options)
	done := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/finish", map[string]any{
		"session_id": started.SessionID, "credential": json.RawMessage(response), "name": "Laptop",
	})
	return rec.Code, "", done.Code, done.Body.String()
}

// TestPasskeySignupBeginAnswersAlikeForATakenAddress checks that starting a
// passkey sign-up answers the same for a free address, one that already has
// an account and one on a domain an organisation manages, and claims nothing,
// so a second start for the same address works; the taken and managed ones are
// refused when the ceremony finishes, with the same neutral answer and no
// account created, and the free one signs up.
func TestPasskeySignupBeginAnswersAlikeForATakenAddress(t *testing.T) {
	h := &Handler{Service: signInService(t)}
	srv := chi.NewRouter()
	h.MountPublic(srv)
	free := dbtest.Unique("free") + "@example.test"
	taken := dbtest.User(t, uuid.Nil).Email
	managed := dbtest.Unique("x") + "@" + dbtest.Domain(t, dbtest.Tenant(t))

	if rec := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/begin", map[string]any{"email": free}); rec.Code != http.StatusOK {
		t.Fatalf("begin for a free address: %d %s", rec.Code, rec.Body.String())
	}
	refusals := map[string]string{}
	for name, email := range map[string]string{"a taken address": taken, "an address on a managed domain": managed, "a free address begun twice": free} {
		beginStatus, begin, finishStatus, finish := signUp(t, srv, email)
		if beginStatus != http.StatusOK {
			t.Errorf("begin for %s: %d %s, want 200 with options", name, beginStatus, begin)
			continue
		}
		if email == free {
			if finishStatus != http.StatusCreated {
				t.Errorf("finish for %s: %d %s, want 201", name, finishStatus, finish)
			}
			continue
		}
		var got struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(finish), &got); err != nil || finishStatus != http.StatusUnprocessableEntity || got.Error.Code != errs.CodeUnprocessable {
			t.Errorf("finish for %s: %d %s, want 422 %s", name, finishStatus, finish, errs.CodeUnprocessable)
		}
		refusals[name] = got.Error.Message
	}
	if refusals["a taken address"] != refusals["an address on a managed domain"] {
		t.Errorf("the refusals differ: %q and %q", refusals["a taken address"], refusals["an address on a managed domain"])
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE lower(email) = lower($1)`, managed); n != 0 {
		t.Errorf("%d accounts created on a managed domain, want none", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE lower(email) = lower($1)`, taken); n != 1 {
		t.Errorf("%d accounts hold the taken address, want its own one", n)
	}
}

// testPasskey is an authenticator holding one ES256 passkey that signs
// assertions for the relying party newService configures.
type testPasskey struct {
	id  []byte
	key *ecdsa.PrivateKey
}

func newTestPasskey(t *testing.T) testPasskey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testPasskey{id: []byte(dbtest.Unique("credential")), key: key}
}

// publicKey is the passkey's public key as a COSE key.
func (p testPasskey) publicKey(t *testing.T) []byte {
	t.Helper()
	pub, err := p.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := pub.Bytes() // 0x04 || X || Y
	raw, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         int64(webauthncose.P256),
		XCoord:        point[1:33],
		YCoord:        point[33:],
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// assert signs an assertion of challenge with sign counter count.
func (p testPasskey) assert(t *testing.T, challenge string, count uint32) json.RawMessage {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	rpID := sha256.Sum256([]byte("example.test"))
	authData := binary.BigEndian.AppendUint32(append(rpID[:], 0x05), count) // user present and verified
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(slices.Clone(authData), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"id": b64(p.id), "rawId": b64(p.id), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(sig)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestPasskeySecondFactorWithOneConnection checks that a passkey meets a
// sign-in's second-factor challenge with only one connection free: the
// ceremony is spent and the sign counter moves on with the sign-in.
func TestPasskeySecondFactorWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	passkeys := newService(t)
	factors := mfa.NewService(pool, "qeet", nil, "")
	factors.SetWebAuthn(passkeys)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(factors)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	passkey := newTestPasskey(t)
	if _, err := pool.Exec(ctx, `INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key) VALUES ($1, $2, $3)`,
		a.ID, passkey.id, passkey.publicKey(t)); err != nil {
		t.Fatalf("passkey: %v", err)
	}
	res, err := authSvc.Login(ctx, auth.LoginInput{Email: a.Email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil || !slices.Contains(res.Methods, "passkey") {
		t.Fatalf("sign in: %+v, %v; want a challenge a passkey meets", res, err)
	}
	sessionID, options, err := authSvc.BeginMFAPasskey(ctx, res.MFAToken)
	if err != nil {
		t.Fatalf("begin the passkey ceremony: %v", err)
	}
	request, ok := options.(protocol.PublicKeyCredentialRequestOptions)
	if !ok {
		t.Fatalf("assertion options %T", options)
	}
	proof := auth.MFAProof{Passkey: &auth.PasskeyProof{SessionID: sessionID, Credential: passkey.assert(t, request.Challenge.String(), 1)}}

	dbtest.LeaveOneConnection(t)
	pair, _, err := authSvc.CompleteMFALoginWith(ctx, res.MFAToken, proof, "", "")
	if err != nil || pair == nil {
		t.Fatalf("meet the challenge with the passkey: %+v, %v", pair, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.passkey_credentials WHERE credential_id = $1 AND sign_count = 1`, passkey.id); n != 1 {
		t.Error("the sign counter did not move on")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.webauthn_sessions WHERE id = $1`, sessionID); n != 0 {
		t.Error("the ceremony was not spent")
	}
}
