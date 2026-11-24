// Package tokens issues and verifies Qeet ID's access and ID JWTs and its opaque
// refresh tokens. JWTs are signed ES256 or RS256, as the active key's type
// decides, and verify from the public JWKS; each carries a kid (its key's RFC
// 7638 thumbprint). SigningKeyRegistry stores the keyring.
package tokens

import (
	"crypto"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the payload of a Qeet ID access token.
type Claims struct {
	UserID         uuid.UUID      `json:"user_id"`                  // the subject user
	OrganizationID uuid.UUID      `json:"organization_id"`          // the user's organization
	SessionID      uuid.UUID      `json:"sid"`                      // the session the token belongs to
	Scope          string         `json:"scope,omitempty"`          // granted scopes
	ActorType      string         `json:"actor_type,omitempty"`     // "service" or "agent"; empty on user tokens
	AgentID        string         `json:"agent_id,omitempty"`       // set on agent tokens
	Act            *ActClaim      `json:"act,omitempty"`            // RFC 8693 actor, on delegated tokens only
	ClientID       string         `json:"client_id,omitempty"`      // RFC 9068 client; the management API refuses such tokens
	ExchangeDepth  int            `json:"exchange_depth,omitempty"` // RFC 8693 exchanges that produced the token
	Custom         map[string]any `json:"claims,omitempty"`         // Auth Hook claims, nested so they can't shadow registered ones

	jwt.RegisteredClaims
}

// ActClaim identifies the acting party in a delegated token (RFC 8693 §4.1).
type ActClaim struct {
	Subject string `json:"sub"`
}

// Issuer signs and verifies Qeet ID JWTs. It is safe for concurrent use, and
// SigningKeyRegistry.Sync can replace its keyring while it is in use.
type Issuer struct {
	mu         sync.RWMutex           // guards active and verifiers
	active     *signingKey            // the key new tokens are signed with
	verifiers  map[string]*signingKey // kid -> key (active + retired)
	issuer     string                 // the iss claim
	audience   string                 // the aud claim
	accessTTL  time.Duration          // access token lifetime
	refreshTTL time.Duration          // refresh token lifetime
}

// NewIssuer builds an issuer from a PEM-encoded private key (PKCS#8, SEC1 or
// PKCS#1): an EC P-256 key signs ES256, an RSA key of 2048 bits or more signs
// RS256. Generate one with GenerateES256KeyPEM (dev), `openssl ecparam -name
// prime256v1 -genkey` or `openssl genrsa 2048`.
func NewIssuer(privateKeyPEM, issuer, audience string, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	priv, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return newIssuerFromKey(priv, issuer, audience, accessTTL, refreshTTL)
}

func newIssuerFromKey(priv crypto.Signer, issuer, audience string, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	active, err := activeKey(priv)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		active:     active,
		verifiers:  map[string]*signingKey{active.kid: active},
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

// AccessTTL returns how long an access token lasts.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// RefreshTTL returns how long a refresh token lasts.
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }

// JWTIssuer returns the tokens' iss claim.
func (i *Issuer) JWTIssuer() string { return i.issuer }

// JWTAudience returns the tokens' aud claim.
func (i *Issuer) JWTAudience() string { return i.audience }
