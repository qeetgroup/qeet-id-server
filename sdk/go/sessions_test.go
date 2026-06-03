package qeetid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionsVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := jwk{
		Kty: "EC", Crv: "P-256", Kid: "test-kid", Use: "sig",
		X: base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		Y: base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk{pub}})
	}))
	defer srv.Close()

	b64 := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	mint := func(payload map[string]any) string {
		si := b64(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "test-kid"}) + "." + b64(payload)
		d := sha256.Sum256([]byte(si))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return si + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	sessions := newSessions(srv.URL, srv.Client())
	ctx := context.Background()
	now := time.Now().Unix()

	// Valid token → claims populated.
	tok := mint(map[string]any{
		"sub": "usr_1", "user_id": "usr_1", "tenant_id": "tnt_1", "sid": "sess_1",
		"iss": "https://id.test", "aud": "rp", "exp": now + 3600, "iat": now,
	})
	claims, err := sessions.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if claims.UserID != "usr_1" || claims.TenantID != "tnt_1" || claims.SessionID != "sess_1" {
		t.Errorf("claims = %+v", claims)
	}

	// Issuer/audience options enforced.
	if _, err := sessions.Verify(ctx, tok, VerifyOptions{Issuer: "https://id.test", Audience: "rp"}); err != nil {
		t.Errorf("matching iss/aud should pass: %v", err)
	}
	if _, err := sessions.Verify(ctx, tok, VerifyOptions{Issuer: "https://evil"}); err == nil {
		t.Error("wrong issuer must reject")
	}

	// Expired (beyond skew) → reject.
	if _, err := sessions.Verify(ctx, mint(map[string]any{"sub": "u", "exp": now - 3600, "iat": now - 7200})); err == nil {
		t.Error("expired token must reject")
	}

	// Tampered signature → reject.
	bad := tok[:len(tok)-3] + "AAA"
	if bad == tok {
		bad = tok[:len(tok)-3] + "BBB"
	}
	if _, err := sessions.Verify(ctx, bad); err == nil {
		t.Error("tampered token must reject")
	}

	// Signed by a different key → reject.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	si := b64(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "test-kid"}) + "." + b64(map[string]any{"sub": "u", "exp": now + 100})
	d := sha256.Sum256([]byte(si))
	r, s, _ := ecdsa.Sign(rand.Reader, other, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if _, err := sessions.Verify(ctx, si+"."+base64.RawURLEncoding.EncodeToString(sig)); err == nil {
		t.Error("token signed by a different key must reject")
	}
}
