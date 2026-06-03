package qeetid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Claims is the verified content of a Qeet-issued token.
type Claims struct {
	UserID    string
	TenantID  string
	SessionID string
	Scope     string
	Subject   string
	Issuer    string
	ExpiresAt int64
	IssuedAt  int64
	Raw       map[string]any
}

// VerifyOptions tightens verification. ClockSkew defaults to 30s.
type VerifyOptions struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
}

// Sessions verifies ES256 tokens against the issuer's published JWKS. After the
// keys are cached it is fully local — the hosted-aligned way to identify the
// caller without a network round-trip per request.
type Sessions struct {
	jwksURL string
	hc      *http.Client

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

const jwksTTL = 5 * time.Minute

func newSessions(baseURL string, hc *http.Client) *Sessions {
	return &Sessions{jwksURL: baseURL + "/.well-known/jwks.json", hc: hc}
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
}

// Verify checks the token's ES256 signature against the JWKS, then validates
// expiry/issuer/audience. Returns *Claims or an error.
func (s *Sessions) Verify(ctx context.Context, token string, opts ...VerifyOptions) (*Claims, error) {
	var o VerifyOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	skew := o.ClockSkew
	if skew == 0 {
		skew = 30 * time.Second
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "malformed token"}
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, err
	}
	if header.Alg != "ES256" {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "unsupported alg " + header.Alg}
	}

	pub, err := s.resolveKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "malformed signature"}
	}
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], r, ss) {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "signature verification failed"}
	}

	var raw map[string]any
	if err := decodeSegment(parts[1], &raw); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	sk := int64(skew / time.Second)
	exp := int64Claim(raw["exp"])
	if exp == 0 || now > exp+sk {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "token expired"}
	}
	if nbf := int64Claim(raw["nbf"]); nbf != 0 && now+sk < nbf {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "token not yet valid"}
	}
	if o.Issuer != "" && strClaim(raw["iss"]) != o.Issuer {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "issuer mismatch"}
	}
	if o.Audience != "" && !audienceMatches(raw["aud"], o.Audience) {
		return nil, &Error{Status: 401, Code: "invalid_token", Message: "audience mismatch"}
	}

	userID := strClaim(raw["user_id"])
	if userID == "" {
		userID = strClaim(raw["sub"])
	}
	return &Claims{
		UserID:    userID,
		TenantID:  strClaim(raw["tenant_id"]),
		SessionID: strClaim(raw["sid"]),
		Scope:     strClaim(raw["scope"]),
		Subject:   strClaim(raw["sub"]),
		Issuer:    strClaim(raw["iss"]),
		ExpiresAt: exp,
		IssuedAt:  int64Claim(raw["iat"]),
		Raw:       raw,
	}, nil
}

func (s *Sessions) resolveKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if k := s.lookup(kid, false); k != nil {
		return k, nil
	}
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	if k := s.lookup(kid, true); k != nil {
		return k, nil
	}
	return nil, &Error{Status: 401, Code: "invalid_token", Message: "no JWKS key for kid " + kid}
}

func (s *Sessions) lookup(kid string, forceFresh bool) *ecdsa.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil || (!forceFresh && time.Since(s.fetchedAt) > jwksTTL) {
		return nil
	}
	if kid == "" {
		for _, k := range s.keys {
			return k
		}
		return nil
	}
	return s.keys[kid]
}

func (s *Sessions) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.hc.Do(req)
	if err != nil {
		return &Error{Code: "network_error", Message: "JWKS fetch: " + err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return &Error{Status: res.StatusCode, Code: "jwks_error", Message: "JWKS fetch failed"}
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return &Error{Code: "jwks_error", Message: "JWKS decode: " + err.Error()}
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.toECDSA()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	s.mu.Lock()
	s.keys = keys
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	return nil
}

func (k jwk) toECDSA() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key %s/%s", k.Kty, k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
}

func decodeSegment(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return &Error{Status: 401, Code: "invalid_token", Message: "malformed token segment"}
	}
	if err := json.Unmarshal(b, out); err != nil {
		return &Error{Status: 401, Code: "invalid_token", Message: "malformed token segment"}
	}
	return nil
}

func strClaim(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func int64Claim(v any) int64 {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return 0
}

func audienceMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
