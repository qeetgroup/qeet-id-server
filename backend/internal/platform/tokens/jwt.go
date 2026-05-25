// Package tokens issues and verifies the access & refresh JWTs.
// Access tokens are short-lived and carry tenant/user IDs. Refresh tokens
// are opaque random strings stored hashed in auth.refresh_tokens.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	secret     []byte
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(secret, issuer, audience string, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{
		secret:     []byte(secret),
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (i *Issuer) AccessTTL() time.Duration  { return i.accessTTL }
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }
func (i *Issuer) JWTIssuer() string         { return i.issuer }
func (i *Issuer) JWTAudience() string       { return i.audience }
func (i *Issuer) Secret() []byte            { return i.secret }

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
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access: %w", err)
	}
	return s, exp, nil
}

func (i *Issuer) VerifyAccess(raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
	)
	tok, err := parser.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		return i.secret, nil
	})
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
