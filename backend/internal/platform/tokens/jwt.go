// Package tokens issues and verifies the access & refresh JWTs.
// Access tokens are short-lived and carry tenant/user IDs. Refresh tokens
// are opaque random strings stored hashed in auth.refresh_tokens.
//
// Every JWT minted here carries a `kid` header naming the active signing
// key. Verifiers look the kid up in {primary, retired} and reject tokens
// with a missing or unknown kid. Retired keys exist to keep tokens
// signed during a rotation grace window verifiable until they expire —
// register them with AddRetiredKey.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	SessionID uuid.UUID `json:"sid"`
	Scope     string    `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

type Issuer struct {
	primaryKey []byte
	kid        string
	retired    map[string][]byte
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(secret, issuer, audience string, accessTTL, refreshTTL time.Duration) *Issuer {
	keyBytes := []byte(secret)
	return &Issuer{
		primaryKey: keyBytes,
		kid:        deriveKID(keyBytes),
		retired:    map[string][]byte{},
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// deriveKID produces a stable, non-secret-revealing identifier for a key
// by hashing it. Sixteen hex characters is plenty of bits to avoid
// collisions across a realistic rotation history.
func deriveKID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

func (i *Issuer) AccessTTL() time.Duration  { return i.accessTTL }
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }
func (i *Issuer) JWTIssuer() string         { return i.issuer }
func (i *Issuer) JWTAudience() string       { return i.audience }
func (i *Issuer) KID() string               { return i.kid }

// AddRetiredKey registers a previously-active key so tokens signed under
// it can still be verified during the rotation grace window. Callers
// should drop retired keys after the access-token TTL has elapsed since
// rotation.
func (i *Issuer) AddRetiredKey(kid string, key []byte) {
	if kid == "" || len(key) == 0 {
		return
	}
	i.retired[kid] = key
}

// Sign returns a JWS-compact-serialised JWT bearing the given claims.
// The `kid` header is always set to the active key id so verifiers can
// route to the right key during rotation. Callers needing custom claims
// (OIDC ID tokens, service-principal access tokens) should use this
// rather than calling jwt.NewWithClaims directly.
func (i *Issuer) Sign(claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.primaryKey)
}

func (i *Issuer) IssueAccess(userID, tenantID, sessionID uuid.UUID, scopes string) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.accessTTL)
	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Scope:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.audience},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	s, err := i.Sign(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access: %w", err)
	}
	return s, exp, nil
}

// keyFunc resolves the verification key from the kid header. It is the
// single point that enforces "no token may verify without a known kid".
func (i *Issuer) keyFunc(t *jwt.Token) (any, error) {
	raw, ok := t.Header["kid"]
	if !ok {
		return nil, errors.New("missing kid header")
	}
	kid, ok := raw.(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid header")
	}
	if kid == i.kid {
		return i.primaryKey, nil
	}
	if key, ok := i.retired[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown kid: %s", kid)
}

func (i *Issuer) VerifyAccess(raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
	)
	tok, err := parser.ParseWithClaims(raw, &Claims{}, i.keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// NewRefreshToken returns (rawToken, sha256Hash). Only the hash is stored.
func NewRefreshToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	return raw, HashRefresh(raw), nil
}

func HashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
