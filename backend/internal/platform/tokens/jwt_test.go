package tokens

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newIssuer(t *testing.T) *Issuer {
	t.Helper()
	return NewIssuer("test-secret-with-enough-bytes", "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
}

func decodeHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

func TestIssueAccess_AlwaysCarriesKID(t *testing.T) {
	i := newIssuer(t)
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	h := decodeHeader(t, tok)
	if h["kid"] == nil || h["kid"] == "" {
		t.Fatalf("kid header missing: %v", h)
	}
	if h["kid"] != i.KID() {
		t.Errorf("kid = %v, want %s", h["kid"], i.KID())
	}
}

func TestSign_SetsKIDForArbitraryClaims(t *testing.T) {
	i := newIssuer(t)
	claims := jwt.MapClaims{
		"iss": i.JWTIssuer(),
		"aud": i.JWTAudience(),
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	tok, err := i.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	h := decodeHeader(t, tok)
	if h["kid"] != i.KID() {
		t.Errorf("kid = %v, want %s", h["kid"], i.KID())
	}
}

func TestVerifyAccess_RoundTrip(t *testing.T) {
	i := newIssuer(t)
	uid, tid, sid := uuid.New(), uuid.New(), uuid.New()
	tok, _, err := i.IssueAccess(uid, tid, sid, "scope.a scope.b")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.UserID != uid || c.TenantID != tid || c.SessionID != sid {
		t.Errorf("claims round-trip mismatch: %+v", c)
	}
	if c.Scope != "scope.a scope.b" {
		t.Errorf("scope mismatch: %q", c.Scope)
	}
}

func TestVerifyAccess_RejectsTokenWithoutKID(t *testing.T) {
	i := newIssuer(t)
	// Hand-build a token with no kid header.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": i.JWTIssuer(),
		"aud": i.JWTAudience(),
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	delete(tok.Header, "kid")
	signed, err := tok.SignedString(i.primaryKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("VerifyAccess must reject tokens with no kid header")
	} else if !strings.Contains(err.Error(), "kid") {
		t.Errorf("error should mention kid: %v", err)
	}
}

func TestVerifyAccess_RejectsUnknownKID(t *testing.T) {
	i := newIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": i.JWTIssuer(),
		"aud": i.JWTAudience(),
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "definitely-not-a-real-kid"
	signed, err := tok.SignedString(i.primaryKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("VerifyAccess must reject tokens with unknown kid")
	}
}

func TestVerifyAccess_AcceptsRetiredKeyDuringGraceWindow(t *testing.T) {
	// Simulate rotation: rotate the primary key on the issuer, then
	// register the old key as retired. Tokens issued before rotation must
	// still verify.
	oldIssuer := newIssuer(t)
	oldToken, _, err := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	oldKID := oldIssuer.KID()
	oldKey := append([]byte{}, oldIssuer.primaryKey...)

	// New issuer (post-rotation) with the old key registered as retired.
	newIssuer2 := NewIssuer("a-completely-different-rotation-key", oldIssuer.issuer, oldIssuer.audience, oldIssuer.accessTTL, oldIssuer.refreshTTL)
	newIssuer2.AddRetiredKey(oldKID, oldKey)

	if _, err := newIssuer2.VerifyAccess(oldToken); err != nil {
		t.Errorf("retired key should still verify old tokens: %v", err)
	}

	// A token signed under the new primary still verifies.
	newToken, _, err := newIssuer2.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess new: %v", err)
	}
	if _, err := newIssuer2.VerifyAccess(newToken); err != nil {
		t.Errorf("new primary should verify its own tokens: %v", err)
	}
}

func TestVerifyAccess_RejectsTokenAfterRetiredKeyDropped(t *testing.T) {
	// Without the retired key registered, old tokens must NOT verify.
	oldIssuer := newIssuer(t)
	oldToken, _, _ := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	newIssuer2 := NewIssuer("post-rotation-key", oldIssuer.issuer, oldIssuer.audience, oldIssuer.accessTTL, oldIssuer.refreshTTL)
	// Note: no AddRetiredKey.
	if _, err := newIssuer2.VerifyAccess(oldToken); err == nil {
		t.Error("old token should not verify after retired key is dropped")
	}
}

func TestKID_StableAcrossInstancesForSameSecret(t *testing.T) {
	a := NewIssuer("same-secret", "i", "a", time.Hour, time.Hour)
	b := NewIssuer("same-secret", "i", "a", time.Hour, time.Hour)
	if a.KID() != b.KID() {
		t.Errorf("kid must be derived from secret deterministically: %s vs %s", a.KID(), b.KID())
	}
}

func TestKID_ChangesWhenSecretChanges(t *testing.T) {
	a := NewIssuer("secret-one", "i", "a", time.Hour, time.Hour)
	b := NewIssuer("secret-two", "i", "a", time.Hour, time.Hour)
	if a.KID() == b.KID() {
		t.Error("kid must differ for different secrets")
	}
}

func TestVerifyAccess_RejectsTamperedKIDHeader(t *testing.T) {
	// Take a valid token, swap kid to "primary" (or any other string)
	// without re-signing. Verifier must reject because the kid won't
	// resolve to the right key OR the signature won't match the resolved key.
	i := newIssuer(t)
	tok, _, _ := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	parts := strings.Split(tok, ".")
	hdr := map[string]any{"alg": "HS256", "typ": "JWT", "kid": "tampered"}
	newHdr, _ := json.Marshal(hdr)
	parts[0] = base64.RawURLEncoding.EncodeToString(newHdr)
	tampered := strings.Join(parts, ".")
	if _, err := i.VerifyAccess(tampered); err == nil {
		t.Error("tampered kid header must be rejected")
	}
}

func TestNewRefreshToken_HashStable(t *testing.T) {
	raw, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	if raw == "" || hash == "" {
		t.Fatal("raw and hash must be non-empty")
	}
	if HashRefresh(raw) != hash {
		t.Error("HashRefresh must be stable across calls")
	}
}

func TestAddRetiredKey_IgnoresEmptyValues(t *testing.T) {
	i := newIssuer(t)
	i.AddRetiredKey("", []byte("x"))
	i.AddRetiredKey("kid", nil)
	if len(i.retired) != 0 {
		t.Errorf("empty values should not be stored: %v", i.retired)
	}
}
