// Package tokens issues and verifies the access & ID JWTs and the opaque
// refresh tokens. Access/ID tokens are signed with an asymmetric key so that
// any relying party can verify them against the public JWKS at
// /.well-known/jwks.json without holding a shared secret — this is what lets
// Qeet ID act as a real OIDC provider.
//
// The default (and currently only) algorithm is ES256 (ECDSA P-256). The
// issuer is written to be crypto-agile: a key carries its own algorithm, so
// adding RS256/EdDSA or a post-quantum scheme (ML-DSA) later is "register a
// new key type", not a rewrite (see LAUNCH_READINESS.md §9).
//
// Every JWT carries a `kid` header set to the RFC 7638 JWK thumbprint of the
// signing key. Verifiers resolve the kid against the active key plus any
// retired keys; a token with a missing or unknown kid is rejected. Retired
// keys are verify-only public keys kept during a rotation grace window so
// tokens minted under the previous key stay valid until they expire — register
// them with AddRetiredKeysPEM.
package tokens

import (
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
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// p256CoordBytes is the fixed byte length of a P-256 coordinate; JWK x/y must
// be left-padded to this length (RFC 7518 §6.2.1.2).
const p256CoordBytes = 32

type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	SessionID uuid.UUID `json:"sid"`
	Scope     string    `json:"scope,omitempty"`
	// ActorType distinguishes the principal kind on non-user tokens
	// ("service", "agent"); empty on ordinary user tokens. AgentID is set on
	// agent tokens. Both are surfaced by introspection so resource servers
	// (incl. MCP servers) can authorize agents distinctly.
	ActorType string `json:"actor_type,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	// Act is the RFC 8693 actor claim: present on delegated tokens (token
	// exchange with an actor_token), naming the party acting on the subject's
	// behalf — e.g. an AI agent exercising a user's authority. Absent otherwise.
	Act *ActClaim `json:"act,omitempty"`
	// Custom carries tenant-supplied claims from a post-login Auth Hook
	// (authhook.Service.Run), namespaced under "claims" rather than merged into
	// the top level so a hook can never shadow a reserved/registered claim.
	Custom map[string]any `json:"claims,omitempty"`
	jwt.RegisteredClaims
}

// ActClaim identifies the acting party in a delegated token (RFC 8693 §4.1).
type ActClaim struct {
	Subject string `json:"sub"`
}

// signingKey couples a key with its JWS algorithm. priv is nil for verify-only
// (retired) keys; pub is always present and is what we publish in the JWKS.
type signingKey struct {
	kid    string
	alg    string
	method jwt.SigningMethod
	priv   crypto.Signer    // signing — active key only
	pub    crypto.PublicKey // verification + JWKS
}

type Issuer struct {
	active     *signingKey            // the key new tokens are signed with
	verifiers  map[string]*signingKey // kid -> key (active + retired)
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
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
func (i *Issuer) KID() string { return i.active.kid }

// Alg is the active signing algorithm (e.g. "ES256"); exposed for the OIDC
// discovery document's id_token_signing_alg_values_supported.
func (i *Issuer) Alg() string { return i.active.alg }

// AddRetiredKeysPEM registers verify-only public keys so tokens signed under a
// previously-active key still verify during the rotation grace window. The
// argument may contain multiple concatenated PEM blocks ("PUBLIC KEY" SPKI or
// "CERTIFICATE"). The kid is derived from each key, so the operator only needs
// to supply the public key. Returns the number of keys registered. Unparseable
// blocks and duplicates are skipped.
func (i *Issuer) AddRetiredKeysPEM(raw string) int {
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
		i.verifiers[kid] = &signingKey{kid: kid, alg: "ES256", method: jwt.SigningMethodES256, pub: ec}
		n++
	}
	return n
}

// Sign returns a compact JWS bearing the given claims, signed with the active
// key and carrying its kid header. Callers needing custom claims (OIDC ID
// tokens, service-principal access tokens) use this rather than calling
// jwt.NewWithClaims directly so the kid is always set.
func (i *Issuer) Sign(claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(i.active.method, claims)
	tok.Header["kid"] = i.active.kid
	return tok.SignedString(i.active.priv)
}

func (i *Issuer) IssueAccess(userID, tenantID, sessionID uuid.UUID, scopes string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, "", nil)
}

// IssueAccessActor mints an access token like IssueAccess but with an RFC 8693
// actor (act) claim, marking it a delegated token: the subject's authority is
// being exercised by actorSubject (e.g. an AI agent acting for a user).
func (i *Issuer) IssueAccessActor(userID, tenantID, sessionID uuid.UUID, scopes, actorSubject string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, &ActClaim{Subject: actorSubject}, "", nil)
}

// IssueAccessResource mints an access token whose audience carries an RFC 8707
// resource indicator. The platform audience is always retained (so the token
// still verifies on this server's own API via VerifyAccess) and the resource is
// appended, letting a downstream resource server (e.g. an MCP server) confirm
// the token was minted for it. An empty resource behaves like IssueAccess.
func (i *Issuer) IssueAccessResource(userID, tenantID, sessionID uuid.UUID, scopes, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, resource, nil)
}

// IssueAccessClaims mints an access token like IssueAccess but with additional
// tenant-supplied custom claims (see Claims.Custom), sourced from a post-login
// Auth Hook. A nil/empty map behaves like IssueAccess.
func (i *Issuer) IssueAccessClaims(userID, tenantID, sessionID uuid.UUID, scopes string, custom map[string]any) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, nil, "", custom)
}

// IssueAccessActorResource combines IssueAccessActor and IssueAccessResource:
// a delegated (RFC 8693 act) token whose audience is also bound to an RFC 8707
// resource indicator. This is the token-exchange grant's MCP case — an agent
// token scoped to one specific downstream resource server.
func (i *Issuer) IssueAccessActorResource(userID, tenantID, sessionID uuid.UUID, scopes, actorSubject, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, tenantID, sessionID, scopes, &ActClaim{Subject: actorSubject}, resource, nil)
}

func (i *Issuer) issueAccess(userID, tenantID, sessionID uuid.UUID, scopes string, act *ActClaim, resource string, custom map[string]any) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.accessTTL)
	aud := jwt.ClaimStrings{i.audience}
	if resource != "" && resource != i.audience {
		aud = append(aud, resource) // RFC 8707: bind the token to the requested resource
	}
	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Scope:     scopes,
		Act:       act,
		Custom:    custom,
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

// keyFunc resolves the verification key from the kid header. It is the single
// point that enforces "no token may verify without a known kid".
func (i *Issuer) keyFunc(t *jwt.Token) (any, error) {
	raw, ok := t.Header["kid"]
	if !ok {
		return nil, errors.New("missing kid header")
	}
	kid, ok := raw.(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid header")
	}
	k, ok := i.verifiers[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	return k.pub, nil
}

// validMethods is the algorithm allow-list the parser enforces, closing off
// "alg confusion" attacks (e.g. a forged HS256 token, or alg=none). Grows when
// a new signing algorithm is added.
var validMethods = []string{"ES256"}

func (i *Issuer) VerifyAccess(raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
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

// VerifyVC verifies a JWT-serialized Verifiable Credential this issuer signed:
// it checks the signature (via the JWKS keys + kid), the issuer, and expiry,
// but NOT the access-token audience (VCs aren't audience-bound). Returns the
// full claim map so the caller can read the embedded `vc` object. Use this only
// for credentials issued by this server (iss == our issuer).
func (i *Issuer) VerifyVC(raw string) (jwt.MapClaims, error) {
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
		return nil, errors.New("invalid credential")
	}
	return claims, nil
}

// KeyMeta is non-secret signing-key metadata for the admin signing-keys view.
// It deliberately carries no key material (the public coordinates live in the
// JWKS); it only reports the key's id, algorithm, use, and rotation status.
type KeyMeta struct {
	Kid    string `json:"kid"`
	Alg    string `json:"alg"`
	Use    string `json:"use"`
	Status string `json:"status"` // "active" | "retired"
}

// KeyInfo returns metadata for every signing key the issuer knows about: the
// active key (status "active") plus any retired verify-only keys still inside
// their rotation grace window (status "retired"). Unlike JWKS it exposes no key
// material, so it's safe to surface in an admin UI.
func (i *Issuer) KeyInfo() []KeyMeta {
	out := make([]KeyMeta, 0, len(i.verifiers))
	for _, k := range i.verifiers {
		status := "retired"
		if i.active != nil && k.kid == i.active.kid {
			status = "active"
		}
		out = append(out, KeyMeta{
			Kid:    k.kid,
			Alg:    k.alg,
			Use:    "sig",
			Status: status,
		})
	}
	return out
}

// Rotate generates a fresh EC P-256 signing key, retires the current active key
// to verify-only status (tokens it signed remain verifiable), and returns the new
// private key's PEM and kid. The caller MUST persist the returned PEM as the new
// JWT_SIGNING_KEY before the process restarts; until then the new key is in-memory
// only. This method is safe to call at runtime — new tokens will immediately be
// signed by the new key.
func (i *Issuer) Rotate() (privKeyPEM string, newKID string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	kid, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("thumbprint: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	newKey := &signingKey{
		kid:    kid,
		alg:    "ES256",
		method: jwt.SigningMethodES256,
		priv:   priv,
		pub:    &priv.PublicKey,
	}

	// Retire the current active key: keep a verify-only copy in verifiers so
	// tokens signed by the old key continue to verify during the grace window.
	if old := i.active; old != nil {
		i.verifiers[old.kid] = &signingKey{
			kid:    old.kid,
			alg:    old.alg,
			method: old.method,
			pub:    old.pub,
			// priv intentionally nil — verify-only
		}
	}

	i.verifiers[kid] = newKey
	i.active = newKey
	return string(pemBytes), kid, nil
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

// JWKS returns every public key a relying party may need to verify a Qeet ID
// token: the active signing key plus any retired keys still inside their grace
// window.
func (i *Issuer) JWKS() []JWK {
	out := make([]JWK, 0, len(i.verifiers))
	for _, k := range i.verifiers {
		ec, ok := k.pub.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		out = append(out, JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   coord(ec.X),
			Y:   coord(ec.Y),
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

func HashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// =====================================================================
// Key generation & parsing helpers
// =====================================================================

// GenerateES256KeyPEM mints a fresh ES256 (P-256) private key as a PKCS#8 PEM.
// Used for dev convenience (ephemeral key when JWT_SIGNING_KEY is unset) and as
// the building block for the key-rotation runbook.
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

// PublicKeyPEM returns the SPKI ("PUBLIC KEY") PEM for the given EC private-key
// PEM. During rotation, feed the retiring key's output here into
// JWT_RETIRED_KEYS so in-flight tokens keep verifying.
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
	canonical := `{"crv":"P-256","kty":"EC","x":"` + coord(pub.X) + `","y":"` + coord(pub.Y) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// coord encodes a P-256 coordinate as a fixed-length, left-padded base64url
// string per RFC 7518 §6.2.1.2.
func coord(c *big.Int) string {
	b := c.Bytes()
	if len(b) < p256CoordBytes {
		padded := make([]byte, p256CoordBytes)
		copy(padded[p256CoordBytes-len(b):], b)
		b = padded
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
