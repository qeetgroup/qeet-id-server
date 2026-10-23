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

// TestSignupBeginAnswersAlike checks that starting a passkey sign-up with an
// email that already has an account gets the neutral answer.
func TestSignupBeginAnswersAlike(t *testing.T) {
	h := &Handler{Service: newService(t)}
	srv := chi.NewRouter()
	h.MountPublic(srv)
	a := dbtest.User(t, uuid.Nil)

	rec := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/begin", map[string]any{"email": a.Email})
	var got struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusUnprocessableEntity || got.Error.Code != errs.CodeUnprocessable {
		t.Errorf("sign-up with a registered email: %d %s, want %d %s", rec.Code, rec.Body.String(),
			http.StatusUnprocessableEntity, errs.CodeUnprocessable)
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
