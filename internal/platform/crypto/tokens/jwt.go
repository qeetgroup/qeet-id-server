// Package tokens issues and verifies Qeet ID's access and ID JWTs and its opaque
// refresh tokens. JWTs are signed ES256 so any relying party can verify them
// from the public JWKS; each carries a kid (its key's RFC 7638 thumbprint), and
// a missing or unknown kid is rejected. SigningKeyRegistry stores the keyring.
package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// p256CoordBytes is the fixed byte length of a P-256 coordinate; JWK x/y must
// be left-padded to this length (RFC 7518 §6.2.1.2).
const p256CoordBytes = 32

// Claims is the payload of a Qeet ID access token.
type Claims struct {
	UserID        uuid.UUID      `json:"user_id"`                  // the subject user
	TenantID      uuid.UUID      `json:"tenant_id"`                // the user's organisation
	SessionID     uuid.UUID      `json:"sid"`                      // the session the token belongs to
	Scope         string         `json:"scope,omitempty"`          // granted scopes
	ActorType     string         `json:"actor_type,omitempty"`     // "service" or "agent"; empty on user tokens
	AgentID       string         `json:"agent_id,omitempty"`       // set on agent tokens
	Act           *ActClaim      `json:"act,omitempty"`            // RFC 8693 actor, on delegated tokens only
	ClientID      string         `json:"client_id,omitempty"`      // RFC 9068 client; the management API refuses such tokens
	ExchangeDepth int            `json:"exchange_depth,omitempty"` // RFC 8693 exchanges that produced the token
	Custom        map[string]any `json:"claims,omitempty"`         // Auth Hook claims, nested so they can't shadow registered ones

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

// NewIssuer builds an ES256 issuer from a PEM-encoded EC P-256 private key
// (PKCS#8 "PRIVATE KEY" or SEC1 "EC PRIVATE KEY"). Generate one with
// GenerateES256KeyPEM (dev) or `openssl ecparam -name prime256v1 -genkey`.
func NewIssuer(privateKeyPEM, issuer, audience string, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	priv, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return newIssuerFromKey(priv, issuer, audience, accessTTL, refreshTTL)
}

func newIssuerFromKey(priv *ecdsa.PrivateKey, issuer, audience string, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("signing key must use the P-256 curve (ES256)")
	}
	kid, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	active := &signingKey{
		kid:    kid,
		alg:    "ES256",
		status: "active",
		method: jwt.SigningMethodES256,
		priv:   priv,
		pub:    &priv.PublicKey,
	}
	return &Issuer{
		active:     active,
		verifiers:  map[string]*signingKey{kid: active},
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func (i *Issuer) AccessTTL() time.Duration  { return i.accessTTL }
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }
func (i *Issuer) JWTIssuer() string         { return i.issuer }
func (i *Issuer) JWTAudience() string       { return i.audience }

// KID is the active signing key's id (its RFC 7638 JWK thumbprint).
func (i *Issuer) KID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.active.kid
}

// Alg is the active signing algorithm (e.g. "ES256"); exposed for the OIDC
// discovery document's id_token_signing_alg_values_supported.
func (i *Issuer) Alg() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.active.alg
}

// AddRetiredKeysPEM registers the P-256 keys in raw (concatenated "PUBLIC KEY"
// or "CERTIFICATE" PEM blocks) as verify-only, so tokens signed before a
// rotation still verify. It returns the number added, skipping bad blocks and
// duplicates.
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
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			continue
		}
		kid, err := thumbprint(ec)
		if err != nil {
			continue
		}
		if _, exists := i.verifiers[kid]; exists {
			continue
		}
		i.verifiers[kid] = &signingKey{kid: kid, alg: "ES256", status: "retired", method: jwt.SigningMethodES256, pub: ec}
		n++
	}
	return n
}

// LoadRetiredKeysPEM is the strict form of AddRetiredKeysPEM: any malformed or
// non-P-256 block is an error, so a replica can't silently lose rotation grace.
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
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return count, errors.New("JWT verification keys must use P-256")
		}
		kid, err := thumbprint(ec)
		if err != nil {
			return count, err
		}
		if _, exists := i.verifiers[kid]; exists {
			continue
		}
		i.verifiers[kid] = &signingKey{kid: kid, alg: "ES256", status: "retired", method: jwt.SigningMethodES256, pub: ec}
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
	priv, err := parseECPrivateKey(activePrivatePEM)
	if err != nil {
		return fmt.Errorf("parse active signing key: %w", err)
	}
	if priv.Curve != elliptic.P256() {
		return errors.New("active signing key must use P-256")
	}
	activeKID, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return err
	}
	active := &signingKey{
		kid: activeKID, alg: "ES256", status: "active",
		method: jwt.SigningMethodES256, priv: priv, pub: &priv.PublicKey,
	}
	verifiers := map[string]*signingKey{activeKID: active}
	for _, entry := range verificationKeys {
		block, rest := pem.Decode([]byte(entry.PEM))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("invalid registry verification-key PEM")
		}
		publicKey, err := publicKeyFromBlock(block)
		if err != nil {
			return fmt.Errorf("parse registry verification key: %w", err)
		}
		ec, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return errors.New("registry verification keys must use P-256")
		}
		kid, err := thumbprint(ec)
		if err != nil {
			return err
		}
		if entry.KID != "" && entry.KID != kid {
			return errors.New("registry verification key does not match its kid")
		}
		if kid == activeKID {
			continue
		}
		status := entry.Status
		if status != "candidate" && status != "retired" {
			return fmt.Errorf("invalid registry key status %q", status)
		}
		verifiers[kid] = &signingKey{
			kid: kid, alg: "ES256", status: status,
			retireAt: entry.RetireAt, method: jwt.SigningMethodES256, pub: ec,
		}
	}
	i.mu.Lock()
	i.active = active
	i.verifiers = verifiers
	i.mu.Unlock()
	return nil
}

// IssueAccess mints a first-party access token for the platform audience and
// returns it with its expiry.
func (i *Issuer) IssueAccess(userID, tenantID, sessionID uuid.UUID, scopes string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, "", nil, "", time.Time{}, 0)
}

// IssueAccessActor mints an access token like IssueAccess but with an RFC 8693
// actor (act) claim, marking it a delegated token: the subject's authority is
// being exercised by actorSubject (e.g. an AI agent acting for a user).
func (i *Issuer) IssueAccessActor(userID, tenantID, sessionID uuid.UUID, scopes, actorSubject string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, &ActClaim{Subject: actorSubject}, "", nil, "", time.Time{}, 0)
}

// IssueAccessResource mints an access token whose audience is the RFC 8707
// resource alone, so this server's API and every other service refuse it. An
// empty resource behaves like IssueAccess.
func (i *Issuer) IssueAccessResource(userID, tenantID, sessionID uuid.UUID, scopes, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, resource, nil, "", time.Time{}, 0)
}

// IssueAccessClaims mints an access token like IssueAccess but with additional
// tenant-supplied custom claims (see Claims.Custom), sourced from a post-login
// Auth Hook. A nil/empty map behaves like IssueAccess.
func (i *Issuer) IssueAccessClaims(userID, tenantID, sessionID uuid.UUID, scopes string, custom map[string]any) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, "", custom, "", time.Time{}, 0)
}

// IssueSessionAccess mints the access token of a first-party session, like
// IssueAccessClaims, but never past sessionEnd: a token issued shortly before
// its session's maximum age ends with the session instead of outliving it.
func (i *Issuer) IssueSessionAccess(userID, tenantID, sessionID uuid.UUID, custom map[string]any, sessionEnd time.Time) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, "", nil, "", custom, "", sessionEnd, 0)
}

// IssueAccessActorResource combines IssueAccessActor and IssueAccessResource: a
// delegated (RFC 8693 act) token whose audience is one RFC 8707 resource, such
// as an agent's token for a single MCP server.
func (i *Issuer) IssueAccessActorResource(userID, tenantID, sessionID uuid.UUID, scopes, actorSubject, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, &ActClaim{Subject: actorSubject}, resource, nil, "", time.Time{}, 0)
}

// ClientAccess describes an access token issued to an application on a
// user's behalf (see IssueClientAccess).
type ClientAccess struct {
	UserID, TenantID, SessionID uuid.UUID // the token's subject, organisation and session
	Scopes                      string    // granted scopes
	ActorSubject                string    // if set, adds an RFC 8693 act claim
	Resource                    string    // if set, the RFC 8707 resource that is the audience
	ClientID                    string    // the application the token is issued to
	NotAfter                    time.Time // if set, the latest expiry; an exchanged token never outlives its source
	ExchangeDepth               int       // token exchanges that produced this token (0: none)
}

// IssueClientAccess mints the access token an application receives from the
// authorization server. It carries client_id, so the management API can tell
// it from the user's own tokens and refuse it.
func (i *Issuer) IssueClientAccess(in ClientAccess) (string, time.Time, error) {
	var act *ActClaim
	if in.ActorSubject != "" {
		act = &ActClaim{Subject: in.ActorSubject}
	}
	return i.issueAccess(in.UserID, in.TenantID, in.SessionID, in.Scopes, act, in.Resource, nil, in.ClientID, in.NotAfter, in.ExchangeDepth)
}

func (i *Issuer) issueAccess(userID, tenantID, sessionID uuid.UUID, scopes string, act *ActClaim, resource string, custom map[string]any, clientID string, notAfter time.Time, exchangeDepth int) (string, time.Time, error) {
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
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Scope:     scopes,
		Act:       act,
		Custom:    custom,
		ClientID:  clientID,
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
// missing or unknown kid and a retired key past its retire_at.
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
	return k.pub, nil
}

// validMethods is the algorithm allow-list the parser enforces, closing off
// "alg confusion" attacks (e.g. a forged HS256 token, or alg=none). Grows when
// a new signing algorithm is added.
var validMethods = []string{"ES256"}

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

// JWK is a public JSON Web Key as published at /.well-known/jwks.json.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
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
		ec, ok := k.pub.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		x, y, err := coords(ec)
		if err != nil {
			continue
		}
		out = append(out, JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   x,
			Y:   y,
			Use: "sig",
			Alg: k.alg,
			Kid: k.kid,
		})
	}
	return out
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

// PublicKeyPEM returns the SPKI ("PUBLIC KEY") PEM for an EC private key, the
// form JWT_RETIRED_KEYS accepts.
func PublicKeyPEM(privateKeyPEM string) (string, error) {
	priv, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (want EC/PKCS#8 private key)", block.Type)
	}
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

// thumbprint computes the RFC 7638 JWK thumbprint of an EC public key and
// returns it base64url-encoded — a stable, non-secret-revealing kid that any
// JWKS consumer can recompute.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub.Curve != elliptic.P256() {
		return "", errors.New("thumbprint: only P-256 supported")
	}
	// RFC 7638 §3.2: members in lexicographic order, no whitespace. The values
	// are base64url and need no JSON escaping, so a literal is safe and exact.
	x, y, err := coords(pub)
	if err != nil {
		return "", err
	}
	canonical := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
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
