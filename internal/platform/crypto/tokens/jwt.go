// Package tokens issues and verifies Qeet ID's access and ID JWTs and its opaque
// refresh tokens. JWTs are signed ES256 or RS256, as the active key's type
// decides, and verify from the public JWKS; each carries a kid (its key's RFC
// 7638 thumbprint). SigningKeyRegistry stores the keyring.
package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// p256CoordBytes is the fixed byte length of a P-256 coordinate; JWK x/y must
// be left-padded to this length (RFC 7518 §6.2.1.2).
const p256CoordBytes = 32

// minRSAKeyBits is the smallest RSA key RS256 may use (RFC 7518 §3.3).
const minRSAKeyBits = 2048

// errUnsupportedKey is a key of a kind tokens are not signed with.
var errUnsupportedKey = errors.New("a signing key must be EC P-256 (ES256) or RSA of 2048 bits or more (RS256)")

// Claims is the payload of a Qeet ID access token.
type Claims struct {
	UserID         uuid.UUID      `json:"user_id"`                  // the subject user
	OrganizationID uuid.UUID      `json:"tenant_id"`                // the user's organization
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

// signingKey couples a key with its JWS algorithm. priv is nil for verify-only
// (retired) keys; pub is always present and is what we publish in the JWKS.
type signingKey struct {
	kid      string            // key ID
	alg      string            // signing algorithm
	status   string            // "candidate", "active" or "retired"
	retireAt *time.Time        // when a retired key stops verifying
	method   jwt.SigningMethod // the JWT signing method
	priv     crypto.Signer     // signing — active key only
	pub      crypto.PublicKey  // verification + JWKS
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

// verifierFor returns the keyring entry for pub: its kid and the one algorithm
// it signs, ES256 for P-256 and RS256 for RSA of 2048 bits or more.
func verifierFor(pub crypto.PublicKey, status string) (*signingKey, error) {
	var method jwt.SigningMethod
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errUnsupportedKey
		}
		method = jwt.SigningMethodES256
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSAKeyBits {
			return nil, errUnsupportedKey
		}
		method = jwt.SigningMethodRS256
	default:
		return nil, errUnsupportedKey
	}
	kid, err := thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &signingKey{kid: kid, alg: method.Alg(), status: status, method: method, pub: pub}, nil
}

// activeKey returns the keyring entry that signs with priv.
func activeKey(priv crypto.Signer) (*signingKey, error) {
	key, err := verifierFor(priv.Public(), "active")
	if err != nil {
		return nil, err
	}
	key.priv = priv
	return key, nil
}

// AccessTTL returns how long an access token lasts.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// RefreshTTL returns how long a refresh token lasts.
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }

// JWTIssuer returns the tokens' iss claim.
func (i *Issuer) JWTIssuer() string { return i.issuer }

// JWTAudience returns the tokens' aud claim.
func (i *Issuer) JWTAudience() string { return i.audience }

// KID is the active signing key's id (its RFC 7638 JWK thumbprint).
func (i *Issuer) KID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.active.kid
}

// Alg is the active key's signing algorithm, "ES256" or "RS256"; exposed for
// the OIDC discovery document's id_token_signing_alg_values_supported.
func (i *Issuer) Alg() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.active.alg
}

// AddRetiredKeysPEM registers the keys in raw (concatenated "PUBLIC KEY" or
// "CERTIFICATE" PEM blocks) as verify-only, so tokens signed before a rotation
// still verify. It returns the number added, skipping bad blocks, keys of
// another kind and duplicates.
func (i *Issuer) AddRetiredKeysPEM(raw string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	rest := []byte(raw)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pub, err := publicKeyFromBlock(block)
		if err != nil {
			continue
		}
		key, err := verifierFor(pub, "retired")
		if err != nil {
			continue
		}
		if _, exists := i.verifiers[key.kid]; exists {
			continue
		}
		i.verifiers[key.kid] = key
		n++
	}
	return n
}

// LoadRetiredKeysPEM is the strict form of AddRetiredKeysPEM: a malformed block
// or a key of another kind is an error, so a replica can't silently lose
// rotation grace.
func (i *Issuer) LoadRetiredKeysPEM(raw string) (int, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	rest := []byte(raw)
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return count, errors.New("invalid JWT verification-key PEM")
		}
		rest = remaining
		pub, err := publicKeyFromBlock(block)
		if err != nil {
			return count, fmt.Errorf("parse JWT verification key: %w", err)
		}
		key, err := verifierFor(pub, "retired")
		if err != nil {
			return count, fmt.Errorf("JWT verification key: %w", err)
		}
		if _, exists := i.verifiers[key.kid]; exists {
			continue
		}
		i.verifiers[key.kid] = key
		count++
	}
	return count, nil
}

// Sign returns a compact JWS of claims signed with the active key, with its kid
// header set. Use it rather than jwt.NewWithClaims so the kid is never missing.
func (i *Issuer) Sign(claims jwt.Claims) (string, error) {
	i.mu.RLock()
	active := i.active
	i.mu.RUnlock()
	if active == nil || active.priv == nil {
		return "", errors.New("no active signing key")
	}
	tok := jwt.NewWithClaims(active.method, claims)
	tok.Header["kid"] = active.kid
	return tok.SignedString(active.priv)
}

type verificationKeyPEM struct {
	KID      string
	PEM      string
	Status   string
	RetireAt *time.Time
}

// replaceKeyring parses a complete registry snapshot before atomically
// publishing it. In-flight sign/verify/JWKS calls see either the old snapshot
// or the new one, never a partially-updated map.
func (i *Issuer) replaceKeyring(activePrivatePEM string, verificationKeys []verificationKeyPEM) error {
	priv, err := parsePrivateKey(activePrivatePEM)
	if err != nil {
		return fmt.Errorf("parse active signing key: %w", err)
	}
	active, err := activeKey(priv)
	if err != nil {
		return fmt.Errorf("active signing key: %w", err)
	}
	verifiers := map[string]*signingKey{active.kid: active}
	for _, entry := range verificationKeys {
		block, rest := pem.Decode([]byte(entry.PEM))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("invalid registry verification-key PEM")
		}
		publicKey, err := publicKeyFromBlock(block)
		if err != nil {
			return fmt.Errorf("parse registry verification key: %w", err)
		}
		key, err := verifierFor(publicKey, entry.Status)
		if err != nil {
			return fmt.Errorf("registry verification key: %w", err)
		}
		if entry.KID != "" && entry.KID != key.kid {
			return errors.New("registry verification key does not match its kid")
		}
		if key.kid == active.kid {
			continue
		}
		if key.status != "candidate" && key.status != "retired" {
			return fmt.Errorf("invalid registry key status %q", key.status)
		}
		key.retireAt = entry.RetireAt
		verifiers[key.kid] = key
	}
	i.mu.Lock()
	i.active = active
	i.verifiers = verifiers
	i.mu.Unlock()
	return nil
}

// IssueAccess mints a first-party access token for the platform audience and
// returns it with its expiry.
func (i *Issuer) IssueAccess(userID, organizationID, sessionID uuid.UUID, scopes string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, "", nil, "", time.Time{}, 0)
}

// IssueAccessActor mints an access token like IssueAccess but with an RFC 8693
// actor (act) claim, marking it a delegated token: the subject's authority is
// being exercised by actorSubject (e.g. an AI agent acting for a user).
func (i *Issuer) IssueAccessActor(userID, organizationID, sessionID uuid.UUID, scopes, actorSubject string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, &ActClaim{Subject: actorSubject}, "", nil, "", time.Time{}, 0)
}

// IssueAccessResource mints an access token whose audience is the RFC 8707
// resource alone, so this server's API and every other service refuse it. An
// empty resource behaves like IssueAccess.
func (i *Issuer) IssueAccessResource(userID, organizationID, sessionID uuid.UUID, scopes, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, resource, nil, "", time.Time{}, 0)
}

// IssueAccessClaims mints an access token like IssueAccess but with additional
// organization-supplied custom claims (see Claims.Custom), sourced from a post-login
// Auth Hook. A nil/empty map behaves like IssueAccess.
func (i *Issuer) IssueAccessClaims(userID, organizationID, sessionID uuid.UUID, scopes string, custom map[string]any) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, "", custom, "", time.Time{}, 0)
}

// IssueSessionAccess mints the access token of a first-party session, like
// IssueAccessClaims, but never past sessionEnd: a token issued shortly before
// its session's maximum age ends with the session instead of outliving it.
func (i *Issuer) IssueSessionAccess(userID, organizationID, sessionID uuid.UUID, custom map[string]any, sessionEnd time.Time) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, "", nil, "", custom, "", sessionEnd, 0)
}

// IssueAccessActorResource combines IssueAccessActor and IssueAccessResource: a
// delegated (RFC 8693 act) token whose audience is one RFC 8707 resource, such
// as an agent's token for a single MCP server.
func (i *Issuer) IssueAccessActorResource(userID, organizationID, sessionID uuid.UUID, scopes, actorSubject, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, &ActClaim{Subject: actorSubject}, resource, nil, "", time.Time{}, 0)
}

// ClientAccess describes an access token issued to an application on a
// user's behalf (see IssueClientAccess).
type ClientAccess struct {
	UserID, OrganizationID, SessionID uuid.UUID // the token's subject, organization and session
	Scopes                            string    // granted scopes
	ActorSubject                      string    // if set, adds an RFC 8693 act claim
	Resource                          string    // if set, the RFC 8707 resource that is the audience
	ClientID                          string    // the application the token is issued to
	NotAfter                          time.Time // if set, the latest expiry; an exchanged token never outlives its source
	ExchangeDepth                     int       // token exchanges that produced this token (0: none)
}

// IssueClientAccess mints the access token an application receives from the
// authorization server. It carries client_id, so the management API can tell
// it from the user's own tokens and refuse it.
func (i *Issuer) IssueClientAccess(in ClientAccess) (string, time.Time, error) {
	var act *ActClaim
	if in.ActorSubject != "" {
		act = &ActClaim{Subject: in.ActorSubject}
	}
	return i.issueAccess(in.UserID, in.OrganizationID, in.SessionID, in.Scopes, act, in.Resource, nil, in.ClientID, in.NotAfter, in.ExchangeDepth)
}

func (i *Issuer) issueAccess(userID, organizationID, sessionID uuid.UUID, scopes string, act *ActClaim, resource string, custom map[string]any, clientID string, notAfter time.Time, exchangeDepth int) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.accessTTL)
	if !notAfter.IsZero() && notAfter.Before(exp) {
		exp = notAfter.UTC()
	}
	// RFC 8707: a token issued for a resource is for that resource alone, so
	// the platform API (which requires its own audience) and every other
	// service refuse it.
	aud := jwt.ClaimStrings{i.audience}
	if resource != "" {
		aud = jwt.ClaimStrings{resource}
	}
	claims := Claims{
		UserID:         userID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		Scope:          scopes,
		Act:            act,
		Custom:         custom,
		ClientID:       clientID,
		// How many exchanges deep the token is, so a chain can be bounded.
		ExchangeDepth: exchangeDepth,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  aud,
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

// keyFunc returns the verification key named by the kid header. It rejects a
// missing or unknown kid, a retired key past its retire_at, and a token signed
// with an algorithm other than that key's own.
func (i *Issuer) keyFunc(t *jwt.Token) (any, error) {
	raw, ok := t.Header["kid"]
	if !ok {
		return nil, errors.New("missing kid header")
	}
	kid, ok := raw.(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid header")
	}
	i.mu.RLock()
	k, ok := i.verifiers[kid]
	i.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	if k.status == "retired" && k.retireAt != nil && !time.Now().Before(*k.retireAt) {
		return nil, fmt.Errorf("expired retired kid: %s", kid)
	}
	if t.Method.Alg() != k.alg {
		return nil, fmt.Errorf("kid %s does not sign %s", kid, t.Method.Alg())
	}
	return k.pub, nil
}

// validMethods is the algorithm allow-list the parser enforces, closing off
// "alg confusion" attacks (e.g. a forged HS256 token, or alg=none). keyFunc
// then holds each key to its own algorithm.
var validMethods = []string{"ES256", "RS256"}

// VerifyAccess verifies an access token issued for the platform audience.
func (i *Issuer) VerifyAccess(raw string) (*Claims, error) {
	return i.verifyAccess(raw, jwt.WithAudience(i.audience))
}

// VerifyAccessFor verifies an access token whose audience includes audience,
// such as a resource server checking a token issued for it (RFC 8707).
func (i *Issuer) VerifyAccessFor(raw, audience string) (*Claims, error) {
	return i.verifyAccess(raw, jwt.WithAudience(audience))
}

// VerifyAccessAnyAudience verifies an access token's signature, issuer and
// lifetime whatever its audience. Only for introspection, which then decides
// whether the caller may see the token at all.
func (i *Issuer) VerifyAccessAnyAudience(raw string) (*Claims, error) {
	return i.verifyAccess(raw)
}

func (i *Issuer) verifyAccess(raw string, opts ...jwt.ParserOption) (*Claims, error) {
	parser := jwt.NewParser(append([]jwt.ParserOption{
		jwt.WithValidMethods(validMethods),
		jwt.WithIssuer(i.issuer),
	}, opts...)...)
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

// ErrNotCredential is a token this issuer signed that is not a verifiable
// credential, such as an access or ID token.
var ErrNotCredential = errors.New("not a verifiable credential")

// VerifyVC verifies a JWT Verifiable Credential this issuer signed (signature,
// kid, issuer and expiry, but no audience) and returns its claims, including the
// embedded vc object. Any other token this issuer signed is ErrNotCredential.
func (i *Issuer) VerifyVC(raw string) (jwt.MapClaims, error) {
	claims, err := i.VerifySigned(raw)
	if err != nil {
		return nil, err
	}
	if !isCredential(claims) {
		return nil, ErrNotCredential
	}
	return claims, nil
}

// VerifySigned verifies a token this issuer signed (signature, kid, issuer and
// lifetime) whatever its audience or kind, and returns its claims. Callers
// check the claims that identify the kind of token they expect.
func (i *Issuer) VerifySigned(raw string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithIssuer(i.issuer),
	)
	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, i.keyFunc)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// isCredential reports whether claims hold a vc object whose type includes
// VerifiableCredential, as a JWT-encoded credential does (VC Data Model 1.1
// §6.3.1).
func isCredential(claims jwt.MapClaims) bool {
	vc, ok := claims["vc"].(map[string]any)
	if !ok {
		return false
	}
	switch types := vc["type"].(type) {
	case string:
		return types == "VerifiableCredential"
	case []any:
		for _, t := range types {
			if t == "VerifiableCredential" {
				return true
			}
		}
	}
	return false
}

// VerifySignedAnyTime verifies a token this issuer signed (signature and
// issuer) whatever its lifetime says: for an id_token_hint, which a sign-out
// request may present after the ID token has expired (OIDC RP-Initiated
// Logout §2).
func (i *Issuer) VerifySignedAnyTime(raw string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithIssuer(i.issuer),
		jwt.WithoutClaimsValidation(),
	)
	claims := jwt.MapClaims{}
	if _, err := parser.ParseWithClaims(raw, claims, i.keyFunc); err != nil {
		return nil, err
	}
	if iss, _ := claims.GetIssuer(); iss != i.issuer {
		return nil, errors.New("issuer mismatch")
	}
	return claims, nil
}

// KeyMeta is non-secret signing-key metadata for the admin signing-keys view.
// It deliberately carries no key material (the public coordinates live in the
// JWKS); it only reports the key's id, algorithm, use, and rotation status.
type KeyMeta struct {
	Kid      string     `json:"kid"`                 // key ID
	Alg      string     `json:"alg"`                 // signing algorithm
	Use      string     `json:"use"`                 // JWK use: "sig"
	Status   string     `json:"status"`              // "candidate", "active" or "retired"
	RetireAt *time.Time `json:"retire_at,omitempty"` // when a retired key stops verifying
}

// KeyInfo returns metadata, without key material, for every key that can still
// verify: the active key, candidates, and retired keys inside their grace window.
func (i *Issuer) KeyInfo() []KeyMeta {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]KeyMeta, 0, len(i.verifiers))
	for _, k := range i.verifiers {
		if k.status == "retired" && k.retireAt != nil && !time.Now().Before(*k.retireAt) {
			continue
		}
		status := k.status
		if status == "" {
			status = "retired"
		}
		if i.active != nil && k.kid == i.active.kid {
			status = "active"
		}
		out = append(out, KeyMeta{
			Kid:      k.kid,
			Alg:      k.alg,
			Use:      "sig",
			Status:   status,
			RetireAt: k.retireAt,
		})
	}
	return out
}

// JWK is a public JSON Web Key as published at /.well-known/jwks.json: an EC
// key has crv, x and y, an RSA key n and e.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// JWKS returns the public keys a relying party may need: the active key,
// candidates, and retired keys still inside their grace window.
func (i *Issuer) JWKS() []JWK {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]JWK, 0, len(i.verifiers))
	for _, k := range i.verifiers {
		if k.status == "retired" && k.retireAt != nil && !time.Now().Before(*k.retireAt) {
			continue
		}
		jwk, err := publicJWK(k.pub)
		if err != nil {
			continue
		}
		jwk.Use, jwk.Alg, jwk.Kid = "sig", k.alg, k.kid
		out = append(out, jwk)
	}
	return out
}

// publicJWK returns the members that hold pub itself: kty with crv, x and y
// for a P-256 key, or with n and e for an RSA key.
func publicJWK(pub crypto.PublicKey) (JWK, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		x, y, err := coords(k)
		if err != nil {
			return JWK{}, err
		}
		return JWK{Kty: "EC", Crv: "P-256", X: x, Y: y}, nil
	case *rsa.PublicKey:
		enc := base64.RawURLEncoding
		return JWK{Kty: "RSA", N: enc.EncodeToString(k.N.Bytes()), E: enc.EncodeToString(big.NewInt(int64(k.E)).Bytes())}, nil
	default:
		return JWK{}, errUnsupportedKey
	}
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

// HashRefresh returns the base64url SHA-256 of a raw refresh token, the form
// that is stored.
func HashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateES256KeyPEM returns a new ES256 (P-256) private key as PKCS#8 PEM.
func GenerateES256KeyPEM() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// parsePrivateKey reads a PEM private key in PKCS#8 ("PRIVATE KEY"), SEC1
// ("EC PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY") form.
func parsePrivateKey(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (want a PKCS#8, EC or RSA private key)", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errUnsupportedKey
	}
	return signer, nil
}

func publicKeyFromBlock(block *pem.Block) (any, error) {
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return c.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported public key PEM type %q", block.Type)
	}
}

// thumbprint computes the RFC 7638 JWK thumbprint of a public key and returns
// it base64url-encoded — a stable, non-secret-revealing kid that any JWKS
// consumer can recompute.
func thumbprint(pub crypto.PublicKey) (string, error) {
	k, err := publicJWK(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638 §3.2: required members in lexicographic order, no whitespace. The
	// values are base64url and need no JSON escaping, so a literal is exact.
	canonical := `{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	if k.Kty == "RSA" {
		canonical = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// coords returns the base64url x and y coordinates of a P-256 public key,
// each fixed-length per RFC 7518 §6.2.1.2.
func coords(pub *ecdsa.PublicKey) (x, y string, err error) {
	b, err := pub.Bytes()
	if err != nil {
		return "", "", err
	}
	if len(b) != 1+2*p256CoordBytes {
		return "", "", errors.New("coords: not a P-256 key")
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(b[1 : 1+p256CoordBytes]), enc.EncodeToString(b[1+p256CoordBytes:]), nil
}
