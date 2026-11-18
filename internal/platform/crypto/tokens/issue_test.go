package tokens

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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

func TestIssueAccessResource_IsForThatResourceAlone(t *testing.T) {
	i, _ := testIssuer(t)
	uid, tid, sid := uuid.New(), uuid.New(), uuid.New()
	const resource = "https://mcp.example/server"

	tok, _, err := i.IssueAccessResource(uid, tid, sid, "read", resource)
	if err != nil {
		t.Fatalf("IssueAccessResource: %v", err)
	}
	// A token issued for a resource is for that resource alone (RFC 8707): the
	// platform API refuses it, and the service it names accepts it.
	if _, err := i.VerifyAccess(tok); err == nil {
		t.Fatal("the platform accepted a token issued for another resource")
	}
	c, err := i.VerifyAccessFor(tok, resource)
	if err != nil {
		t.Fatalf("VerifyAccessFor its own resource: %v", err)
	}
	if auds := []string(c.Audience); len(auds) != 1 || auds[0] != resource {
		t.Errorf("aud = %v, want only %q", auds, resource)
	}
	if _, err := i.VerifyAccessFor(tok, "https://other.example"); err == nil {
		t.Fatal("another service accepted a token issued for this one")
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

func TestIssueAccessClaims_RoundTrips(t *testing.T) {
	i, _ := testIssuer(t)
	custom := map[string]any{"plan": "enterprise", "seats": float64(25)}
	tok, _, err := i.IssueAccessClaims(uuid.New(), uuid.New(), uuid.New(), "", custom)
	if err != nil {
		t.Fatalf("IssueAccessClaims: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.Custom["plan"] != "enterprise" || c.Custom["seats"] != float64(25) {
		t.Errorf("custom claims did not round-trip, got %+v", c.Custom)
	}
}

func TestIssueAccess_NoCustomClaimsByDefault(t *testing.T) {
	i, _ := testIssuer(t)
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.Custom != nil {
		t.Errorf("ordinary access token must not carry custom claims, got %+v", c.Custom)
	}
}

// TestNewRefreshToken_HashStable checks that a refresh token's hash is the
// stored form: the token's SHA-256, base64url.
func TestNewRefreshToken_HashStable(t *testing.T) {
	if got, want := HashRefresh("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"; got != want {
		t.Errorf(`HashRefresh("abc") = %q, want %q`, got, want)
	}
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

// TestAnRSAKeySignsRS256 checks that an issuer given an RSA key signs RS256,
// names the key by its RFC 7638 thumbprint and publishes it as an RSA key.
func TestAnRSAKeySignsRS256(t *testing.T) {
	key := rsaKey()
	enc := base64.RawURLEncoding
	n, e := enc.EncodeToString(key.N.Bytes()), enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	canonical, err := json.Marshal(map[string]string{"e": e, "kty": "RSA", "n": n})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	kid := enc.EncodeToString(sum[:])
	for form, keyPEM := range map[string]string{
		"PKCS#8": privatePEM(t, key),
		"PKCS#1": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
	} {
		i, err := NewIssuer(keyPEM, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatalf("%s: an issuer over an RSA key: %v", form, err)
		}
		if i.KID() != kid || i.Alg() != "RS256" {
			t.Errorf("%s: kid %s signing %s, want the key's thumbprint %s signing RS256", form, i.KID(), i.Alg(), kid)
		}
		tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
		if err != nil {
			t.Fatalf("%s: IssueAccess: %v", form, err)
		}
		if h := decodeHeader(t, tok); h["alg"] != "RS256" || h["kid"] != kid {
			t.Errorf("%s: token header %v, want RS256 and the key's kid", form, h)
		}
		if _, err := i.VerifyAccess(tok); err != nil {
			t.Errorf("%s: the issuer's own token: %v", form, err)
		}
		raw, err := json.Marshal(i.JWKS())
		if err != nil {
			t.Fatal(err)
		}
		var published []map[string]string
		if err := json.Unmarshal(raw, &published); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"kty": "RSA", "n": n, "e": e, "use": "sig", "alg": "RS256", "kid": kid}
		if len(published) != 1 || !maps.Equal(published[0], want) {
			t.Errorf("%s: published keys %s, want only %v", form, raw, want)
		}
	}
}

// The payloads the service-principal and agent token endpoints signed before
// their tokens were minted here, kept as the reference IssueMachineAccess
// must reproduce.
type referenceServiceClaims struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Scope          string    `json:"scope,omitempty"`
	ActorType      string    `json:"actor_type"`
	jwt.RegisteredClaims
}

type referenceAgentClaims struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Scope          string    `json:"scope,omitempty"`
	ActorType      string    `json:"actor_type"`
	AgentID        string    `json:"agent_id"`
	jwt.RegisteredClaims
}

// tokenTimes matches the members that differ between two tokens minted
// apart: their times and their id.
var tokenTimes = regexp.MustCompile(`"(iat|nbf|exp)":\d+|"jti":"[0-9a-f-]{36}"`)

// segments returns a token's decoded header and payload, the payload with its
// times and id blanked, and its lifetime (exp - iat) in seconds.
func segments(t *testing.T, token string) (header, payload string, lifetime int64) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d segments", token, len(parts))
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var times struct{ Iat, Nbf, Exp int64 }
	if err := json.Unmarshal(p, &times); err != nil {
		t.Fatal(err)
	}
	if times.Nbf != times.Iat {
		t.Errorf("nbf %d, want iat %d", times.Nbf, times.Iat)
	}
	return string(h), tokenTimes.ReplaceAllString(string(p), `"$1":0`), times.Exp - times.Iat
}

// TestMachineTokensKeepTheirClaims checks that a service principal's and an
// agent's token carry, byte for byte, the header and claims their endpoints
// signed before, apart from the times and id, and last as long.
func TestMachineTokensKeepTheirClaims(t *testing.T) {
	issuer, _ := testIssuer(t)
	id, organization := uuid.New(), uuid.New()
	registered := func(ttl time.Duration) jwt.RegisteredClaims {
		now := time.Now().UTC()
		return jwt.RegisteredClaims{
			Issuer: issuer.JWTIssuer(), Audience: jwt.ClaimStrings{issuer.JWTAudience()}, Subject: id.String(),
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID: uuid.NewString(),
		}
	}
	for _, tc := range []struct {
		name      string
		in        MachineAccess
		reference jwt.Claims
		lifetime  time.Duration
	}{
		{"a service principal", MachineAccess{Subject: id, OrganizationID: organization, Scopes: []string{"users:read", "audit:read"}},
			referenceServiceClaims{organization, "users:read audit:read", "service", registered(time.Hour)}, time.Hour},
		{"a service principal without scopes", MachineAccess{Subject: id, OrganizationID: organization, Scopes: []string{}},
			referenceServiceClaims{organization, "", "service", registered(time.Hour)}, time.Hour},
		{"an agent", MachineAccess{Subject: id, OrganizationID: organization, Scopes: []string{"agent:invoke"}, Agent: true, TTL: 10 * time.Minute},
			referenceAgentClaims{organization, "agent:invoke", "agent", id.String(), registered(10 * time.Minute)}, 10 * time.Minute},
		{"an agent without scopes", MachineAccess{Subject: id, OrganizationID: organization, Agent: true, TTL: time.Minute},
			referenceAgentClaims{organization, "", "agent", id.String(), registered(time.Minute)}, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			minted, err := issuer.IssueMachineAccess(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			reference, err := issuer.Sign(tc.reference)
			if err != nil {
				t.Fatal(err)
			}
			gotHeader, gotPayload, gotLifetime := segments(t, minted.AccessToken)
			wantHeader, wantPayload, wantLifetime := segments(t, reference)
			if gotHeader != wantHeader {
				t.Errorf("header %s, want %s", gotHeader, wantHeader)
			}
			if gotPayload != wantPayload {
				t.Errorf("claims %s, want %s", gotPayload, wantPayload)
			}
			if gotLifetime != wantLifetime || minted.Lifetime != tc.lifetime || !minted.ExpiresAt.After(time.Now().Add(tc.lifetime-time.Minute)) {
				t.Errorf("lifetime %ds (%v, expires %v), want %ds", gotLifetime, minted.Lifetime, minted.ExpiresAt, wantLifetime)
			}
			if want := strings.Join(tc.in.Scopes, " "); minted.Scope != want {
				t.Errorf("scope %q, want %q", minted.Scope, want)
			}
			claims, err := issuer.VerifyAccess(minted.AccessToken)
			if err != nil || claims.Subject != id.String() || claims.OrganizationID != organization || claims.UserID != uuid.Nil {
				t.Errorf("verified as %+v, %v; want the machine identity's own token on the platform path", claims, err)
			}
		})
	}
}
