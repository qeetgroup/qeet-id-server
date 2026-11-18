package oidcrp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

const (
	clockSkew           = time.Minute // how far a provider's clock may be from ours
	tenantIDPlaceholder = "{tenantid}"
	maxSubjectLen       = 255
)

// SigningAlgorithms are the signatures an ID token may carry: asymmetric only,
// so nothing holding the client secret can make one.
var SigningAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// Rules are what an ID token must match to sign someone in.
type Rules struct {
	Issuer string // the issuer the token must name
	// IssuerTemplate is an issuer with {tenantid} in it, as a provider serving
	// many tenants (Microsoft Entra ID) publishes it: the token's issuer must be
	// it with the token's own tid. It takes the place of Issuer.
	IssuerTemplate string
	TenantIDs      []string // the provider tenants (tid) accepted; none: any
	ClientID       string   // the audience the token must name
	NonceHash      string   // the hash of the nonce the sign-in sent
	Algorithms     []string // a subset of SigningAlgorithms; none: all of them
}

// RulesFor returns rules for a token from the provider that published doc to
// clientID, under whichever tenant, for the sign-in that sent the nonce
// hashed as nonceHash.
func RulesFor(doc Discovery, clientID, nonceHash string) Rules {
	r := Rules{ClientID: clientID, NonceHash: nonceHash}
	if IssuerServesTenants(doc.Issuer) {
		r.IssuerTemplate = doc.Issuer
	} else {
		r.Issuer = doc.Issuer
	}
	return r
}

// IssuerServesTenants reports whether issuer is a template a provider serving
// many tenants publishes, which names each tenant's issuer.
func IssuerServesTenants(issuer string) bool {
	return strings.Contains(issuer, tenantIDPlaceholder)
}

// issuerAllowed reports whether a token from iss, naming the provider tenant
// tid, meets the rules.
func (r Rules) issuerAllowed(iss, tid string) bool {
	if len(r.TenantIDs) > 0 && !slices.Contains(r.TenantIDs, strings.ToLower(tid)) {
		return false
	}
	if r.IssuerTemplate != "" {
		return tid != "" && iss == strings.ReplaceAll(r.IssuerTemplate, tenantIDPlaceholder, tid)
	}
	return r.Issuer != "" && iss == r.Issuer
}

// algorithms returns the signatures the rules accept.
func (r Rules) algorithms() []string {
	if len(r.Algorithms) == 0 {
		return SigningAlgorithms
	}
	var out []string
	for _, alg := range r.Algorithms {
		if slices.Contains(SigningAlgorithms, alg) {
			out = append(out, alg)
		}
	}
	return out
}

// VerifyIDToken checks raw's signature against the provider's keys at jwksURI,
// under the key the token names, and its claims against r: issuer and tenant,
// audience and authorized party, expiry and issue time within a minute, nonce
// and subject. It returns the token's claims.
func (c *Client) VerifyIDToken(ctx context.Context, raw, jwksURI string, r Rules) (jwt.MapClaims, error) {
	algs := r.algorithms()
	if r.ClientID == "" || len(algs) == 0 {
		return nil, errors.New("id_token: no audience or algorithm to check")
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(algs),
		jwt.WithAudience(r.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(c.now),
	)
	if _, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return c.verificationKey(ctx, jwksURI, kid, t.Method.Alg())
	}); err != nil {
		return nil, err
	}
	if iat, err := claims.GetIssuedAt(); err != nil || iat == nil {
		return nil, errors.New("id_token: no iat")
	}
	iss, _ := claims["iss"].(string)
	tid, _ := claims["tid"].(string)
	if !r.issuerAllowed(iss, tid) {
		return nil, fmt.Errorf("id_token: issuer %q (tid %q) not accepted", iss, tid)
	}
	aud, err := claims.GetAudience()
	if err != nil {
		return nil, err
	}
	// OpenID Connect Core §3.1.3.7: a token for several audiences names the
	// client it was issued to.
	azp, _ := claims["azp"].(string)
	if (len(aud) > 1 || azp != "") && azp != r.ClientID {
		return nil, errors.New("id_token: authorized party is not this client")
	}
	nonce, _ := claims["nonce"].(string)
	if nonce == "" || r.NonceHash == "" || subtle.ConstantTimeCompare([]byte(codes.Hash(nonce)), []byte(r.NonceHash)) != 1 {
		return nil, errors.New("id_token: nonce does not match the sign-in")
	}
	if sub, _ := claims["sub"].(string); sub == "" || len(sub) > maxSubjectLen {
		return nil, errors.New("id_token: no usable sub")
	}
	return claims, nil
}
