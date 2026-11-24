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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// p256CoordBytes is the fixed byte length of a P-256 coordinate; JWK x/y must
// be left-padded to this length (RFC 7518 §6.2.1.2).
const p256CoordBytes = 32

// minRSAKeyBits is the smallest RSA key RS256 may use (RFC 7518 §3.3).
const minRSAKeyBits = 2048

// errUnsupportedKey is a key of a kind tokens are not signed with.
var errUnsupportedKey = errors.New("a signing key must be EC P-256 (ES256) or RSA of 2048 bits or more (RS256)")

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
