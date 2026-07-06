package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// testIssuer builds an ES256 issuer over a fresh key and also returns the
// private key so tests can forge tokens (missing/unknown kid, alg confusion).
func testIssuer(t *testing.T) (*Issuer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	i, err := newIssuerFromKey(priv, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return i, priv
}

func publicPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
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

func TestIssueAccessResource_BindsAudienceAndStillVerifies(t *testing.T) {
	i, _ := testIssuer(t)
	uid, tid, sid := uuid.New(), uuid.New(), uuid.New()
	const resource = "https://mcp.example/server"

	tok, _, err := i.IssueAccessResource(uid, tid, sid, "read", resource)
	if err != nil {
		t.Fatalf("IssueAccessResource: %v", err)
	}
	// Critical safety property: a resource-bound token must STILL verify on the
	// platform, because VerifyAccess enforces the platform audience.
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess of resource-bound token: %v", err)
	}
	auds := []string(c.Audience)
	if !slices.Contains(auds, "qeet-test") {
		t.Errorf("aud missing platform audience: %v", auds)
	}
	if !slices.Contains(auds, resource) {
		t.Errorf("aud missing RFC 8707 resource: %v", auds)
	}

	// No resource → a single, platform-only audience (back-compat).
	tok2, _, err := i.IssueAccessResource(uid, tid, sid, "read", "")
	if err != nil {
		t.Fatalf("IssueAccessResource(no resource): %v", err)
	}
	c2, err := i.VerifyAccess(tok2)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if len(c2.Audience) != 1 || c2.Audience[0] != "qeet-test" {
		t.Errorf("no-resource aud = %v, want [qeet-test]", c2.Audience)
	}
}

func TestIssueAccess_AlwaysCarriesKID(t *testing.T) {
	i, _ := testIssuer(t)
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	h := decodeHeader(t, tok)
	if h["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", h["alg"])
	}
	if h["kid"] == nil || h["kid"] == "" {
		t.Fatalf("kid header missing: %v", h)
	}
	if h["kid"] != i.KID() {
		t.Errorf("kid = %v, want %s", h["kid"], i.KID())
	}
}

func TestSign_SetsKIDForArbitraryClaims(t *testing.T) {
	i, _ := testIssuer(t)
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
	if decodeHeader(t, tok)["kid"] != i.KID() {
		t.Errorf("kid mismatch, want %s", i.KID())
	}
}

func TestVerifyAccess_RoundTrip(t *testing.T) {
	i, _ := testIssuer(t)
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

func TestIssueAccess_NoActClaimByDefault(t *testing.T) {
	i, _ := testIssuer(t)
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.Act != nil {
		t.Errorf("ordinary access token must not carry an act claim, got %+v", c.Act)
	}
}

func TestIssueAccessActor_CarriesActClaim(t *testing.T) {
	i, _ := testIssuer(t)
	uid, tid, sid := uuid.New(), uuid.New(), uuid.New()
	agent := "agent-123"
	tok, _, err := i.IssueAccessActor(uid, tid, sid, "doc.read", agent)
	if err != nil {
		t.Fatalf("IssueAccessActor: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	// Delegated token: subject is still the user; act names the acting agent.
	if c.Subject != uid.String() {
		t.Errorf("subject should be the user, got %q", c.Subject)
	}
	if c.Act == nil || c.Act.Subject != agent {
		t.Errorf("act claim must name the actor %q, got %+v", agent, c.Act)
	}
}

func TestVerifyAccess_SurfacesActorClaims(t *testing.T) {
	// Agent/service tokens carry actor_type/agent_id (custom claims); verify they
	// round-trip into Claims so introspection can surface them.
	i, _ := testIssuer(t)
	now := time.Now().UTC()
	tok, err := i.Sign(Claims{
		TenantID:  uuid.New(),
		Scope:     "vault:read",
		ActorType: "agent",
		AgentID:   "agent-xyz",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "qeet-test",
			Audience:  jwt.ClaimStrings{"qeet-test"},
			Subject:   uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.ActorType != "agent" || c.AgentID != "agent-xyz" {
		t.Errorf("actor claims not surfaced: actor_type=%q agent_id=%q", c.ActorType, c.AgentID)
	}
}

func TestVerifyVC_RoundTripAndRejection(t *testing.T) {
	i, _ := testIssuer(t)
	now := time.Now().UTC()
	type vcClaims struct {
		VC map[string]any `json:"vc"`
		jwt.RegisteredClaims
	}
	make := func(iss string) string {
		s, err := i.Sign(vcClaims{
			VC: map[string]any{"type": []string{"VerifiableCredential", "TestCred"}},
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    iss,
				Subject:   "did:example:123",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	// Our credential verifies and the vc claim is accessible.
	claims, err := i.VerifyVC(make("qeet-test"))
	if err != nil {
		t.Fatalf("VerifyVC: %v", err)
	}
	if _, ok := claims["vc"].(map[string]any); !ok {
		t.Error("vc claim missing from verified credential")
	}
	// A credential claiming a different issuer must be rejected.
	if _, err := i.VerifyVC(make("evil-issuer")); err == nil {
		t.Error("VerifyVC must reject a foreign issuer")
	}
}

func TestVerifyAccess_RejectsTokenWithoutKID(t *testing.T) {
	i, priv := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	delete(tok.Header, "kid")
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject token with no kid header")
	} else if !strings.Contains(err.Error(), "kid") {
		t.Errorf("error should mention kid: %v", err)
	}
}

func TestVerifyAccess_RejectsUnknownKID(t *testing.T) {
	i, priv := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "definitely-not-a-real-kid"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject token with unknown kid")
	}
}

// TestVerifyAccess_RejectsHS256Token guards against the classic "alg confusion"
// attack: a token forged with HS256 (treating the public key as an HMAC secret)
// must be rejected because the parser only accepts ES256.
func TestVerifyAccess_RejectsHS256Token(t *testing.T) {
	i, _ := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = i.KID()
	signed, err := tok.SignedString([]byte("attacker-chosen-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject an HS256-signed token (alg confusion)")
	}
}

func TestVerifyAccess_AcceptsRetiredKeyDuringGraceWindow(t *testing.T) {
	oldIssuer, oldPriv := testIssuer(t)
	oldToken, _, err := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	// Post-rotation issuer with a new active key; register the old PUBLIC key.
	newIssuer, _ := testIssuer(t)
	if n := newIssuer.AddRetiredKeysPEM(publicPEM(t, oldPriv)); n != 1 {
		t.Fatalf("AddRetiredKeysPEM registered %d keys, want 1", n)
	}
	if _, err := newIssuer.VerifyAccess(oldToken); err != nil {
		t.Errorf("retired key should still verify old tokens: %v", err)
	}
	// And the new primary still verifies its own tokens.
	newToken, _, _ := newIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if _, err := newIssuer.VerifyAccess(newToken); err != nil {
		t.Errorf("new primary should verify its own tokens: %v", err)
	}
}

func TestVerifyAccess_RejectsTokenAfterRetiredKeyDropped(t *testing.T) {
	oldIssuer, _ := testIssuer(t)
	oldToken, _, _ := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	newIssuer, _ := testIssuer(t) // no retired key registered
	if _, err := newIssuer.VerifyAccess(oldToken); err == nil {
		t.Error("old token must not verify once the retired key is dropped")
	}
}

func TestKID_StableAcrossInstancesForSameKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := newIssuerFromKey(priv, "i", "a", time.Hour, time.Hour)
	b, _ := newIssuerFromKey(priv, "i", "a", time.Hour, time.Hour)
	if a.KID() != b.KID() {
		t.Errorf("kid must be a deterministic thumbprint: %s vs %s", a.KID(), b.KID())
	}
}

func TestKID_ChangesWhenKeyChanges(t *testing.T) {
	a, _ := testIssuer(t)
	b, _ := testIssuer(t)
	if a.KID() == b.KID() {
		t.Error("different keys must produce different kids")
	}
}

func TestVerifyAccess_RejectsTamperedKIDHeader(t *testing.T) {
	i, _ := testIssuer(t)
	tok, _, _ := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	parts := strings.Split(tok, ".")
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "tampered"})
	parts[0] = base64.RawURLEncoding.EncodeToString(hdr)
	if _, err := i.VerifyAccess(strings.Join(parts, ".")); err == nil {
		t.Error("tampered kid header must be rejected")
	}
}

func TestJWKS_PublishesPublicKeys(t *testing.T) {
	i, _ := testIssuer(t)
	ks := i.JWKS()
	if len(ks) != 1 {
		t.Fatalf("JWKS len = %d, want 1", len(ks))
	}
	k := ks[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Use != "sig" || k.Alg != "ES256" {
		t.Errorf("unexpected JWK shape: %+v", k)
	}
	if k.Kid != i.KID() {
		t.Errorf("JWK kid %q must match active KID %q", k.Kid, i.KID())
	}
	if k.X == "" || k.Y == "" {
		t.Error("JWK coordinates must be populated")
	}

	// A retired key shows up too, so RPs can verify in-grace tokens.
	_, oldPriv := testIssuer(t)
	i.AddRetiredKeysPEM(publicPEM(t, oldPriv))
	if len(i.JWKS()) != 2 {
		t.Errorf("JWKS should include the retired key, got %d", len(i.JWKS()))
	}
}

func TestNewIssuer_PEMRoundTrip(t *testing.T) {
	keyPEM, err := GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("GenerateES256KeyPEM: %v", err)
	}
	i, err := NewIssuer(keyPEM, "iss", "aud", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := i.VerifyAccess(tok); err != nil {
		t.Errorf("round-trip verify failed: %v", err)
	}
	// PublicKeyPEM should parse and produce an SPKI block.
	pub, err := PublicKeyPEM(keyPEM)
	if err != nil || !strings.Contains(pub, "PUBLIC KEY") {
		t.Errorf("PublicKeyPEM = %q, err = %v", pub, err)
	}
}

func TestNewIssuer_RejectsBadPEM(t *testing.T) {
	if _, err := NewIssuer("not a pem", "i", "a", time.Hour, time.Hour); err == nil {
		t.Error("NewIssuer must reject non-PEM input")
	}
}

func TestAddRetiredKeysPEM_IgnoresGarbage(t *testing.T) {
	i, _ := testIssuer(t)
	if n := i.AddRetiredKeysPEM(""); n != 0 {
		t.Errorf("empty input registered %d keys", n)
	}
	if n := i.AddRetiredKeysPEM("-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----"); n != 0 {
		t.Errorf("garbage PEM registered %d keys", n)
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
