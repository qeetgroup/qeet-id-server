package tokens

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
