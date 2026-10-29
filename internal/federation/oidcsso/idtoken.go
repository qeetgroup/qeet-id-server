package oidcsso

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

const (
	clockSkew           = time.Minute // how far a provider's clock may be from ours
	tenantIDPlaceholder = "{tenantid}"
	maxSubjectLen       = 255
	maxGroups           = 200
	maxGroupLen         = 256
)

// signingAlgs are the signatures an ID token may carry: asymmetric only, so
// nothing holding the client secret can make one.
var signingAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// idTokenRules are what an ID token must match to sign someone in.
type idTokenRules struct {
	issuer string // the connection's issuer
	// issuerTemplate is the discovery issuer with {tenantid} in it, as a
	// provider serving many tenants (Microsoft Entra ID) publishes it.
	issuerTemplate string
	tenantIDs      []string // the provider tenants (tid) accepted; none: any
	clientID       string   // the audience the token must name
	nonceHash      string   // the hash of the nonce the sign-in sent
}

// rulesFor returns the ID token rules of a sign-in through c whose provider
// published doc. A document naming another issuer is refused, unless it is
// a multi-tenant one and c lists the tenants it accepts, or anyone with an
// account at that provider could sign in.
func rulesFor(c *Connection, doc discovery) (idTokenRules, error) {
	rules := idTokenRules{issuer: c.Issuer, tenantIDs: c.AllowedIdPTenantIDs, clientID: c.ClientID}
	switch {
	case strings.Contains(doc.Issuer, tenantIDPlaceholder):
		if len(c.AllowedIdPTenantIDs) == 0 {
			return idTokenRules{}, fmt.Errorf("discovery issuer %q serves every tenant, and the connection lists none", doc.Issuer)
		}
		rules.issuerTemplate = doc.Issuer
	case doc.Issuer != c.Issuer:
		return idTokenRules{}, fmt.Errorf("discovery issuer %q is not the connection's %q", doc.Issuer, c.Issuer)
	}
	return rules, nil
}

// issuerAllowed reports whether a token from iss, naming the provider tenant
// tid, meets the rules: iss is the connection's issuer or, for a multi-tenant
// provider, the issuer of tid; and tid is accepted when the rules list any.
func (r idTokenRules) issuerAllowed(iss, tid string) bool {
	if len(r.tenantIDs) > 0 && !slices.Contains(r.tenantIDs, strings.ToLower(tid)) {
		return false
	}
	if r.issuerTemplate != "" {
		return tid != "" && iss == strings.ReplaceAll(r.issuerTemplate, tenantIDPlaceholder, tid)
	}
	return iss == r.issuer
}

// verifyIDToken checks raw's signature against the provider's keys at jwksURI
// and its claims against rules: issuer and tenant, audience and authorized
// party, expiry and issue time within clockSkew, nonce and subject. It
// returns the token's claims.
func (c *providerClient) verifyIDToken(ctx context.Context, raw, jwksURI string, rules idTokenRules) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingAlgs),
		jwt.WithAudience(rules.clientID),
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
	if !rules.issuerAllowed(iss, tid) {
		return nil, fmt.Errorf("id_token: issuer %q (tid %q) not accepted", iss, tid)
	}
	aud, err := claims.GetAudience()
	if err != nil {
		return nil, err
	}
	// OpenID Connect Core §3.1.3.7: a token for several audiences names the
	// client it was issued to.
	azp, _ := claims["azp"].(string)
	if (len(aud) > 1 || azp != "") && azp != rules.clientID {
		return nil, errors.New("id_token: authorized party is not this client")
	}
	nonce, _ := claims["nonce"].(string)
	if nonce == "" || rules.nonceHash == "" || subtle.ConstantTimeCompare([]byte(codes.Hash(nonce)), []byte(rules.nonceHash)) != 1 {
		return nil, errors.New("id_token: nonce does not match the sign-in")
	}
	if sub, _ := claims["sub"].(string); sub == "" || len(sub) > maxSubjectLen {
		return nil, errors.New("id_token: no usable sub")
	}
	return claims, nil
}

// profile is what a validated ID token says about the person it signs in.
type profile struct {
	subject    string // the provider's subject, qualified by its issuer
	issuer     string
	email      string // lower-cased
	verified   *bool  // the provider's email_verified; nil when it doesn't say
	name       string // the display name: the name claim, else given and family names
	givenName  string
	familyName string
	groups     []string
}

// profileOf reads claims through the connection's claim mapping. The subject
// is the issuer and sub together, as sub is unique only within its issuer.
func (c *Connection) profileOf(claims jwt.MapClaims) profile {
	text := func(name string) string {
		if name == "" {
			return ""
		}
		v, _ := claims[name].(string)
		return strings.TrimSpace(v)
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	p := profile{
		subject:    iss + "#" + sub,
		issuer:     iss,
		email:      strings.ToLower(text(c.ClaimMapping.Email)),
		name:       text(c.ClaimMapping.Name),
		givenName:  text(c.ClaimMapping.GivenName),
		familyName: text(c.ClaimMapping.FamilyName),
		groups:     groupsOf(claims, c.ClaimMapping.Groups),
	}
	if p.name == "" {
		p.name = strings.TrimSpace(p.givenName + " " + p.familyName)
	}
	// email_verified speaks only for the email claim.
	if c.ClaimMapping.Email == "email" {
		switch v := claims["email_verified"].(type) {
		case bool:
			p.verified = &v
		case string:
			b := strings.EqualFold(v, "true")
			p.verified = &b
		}
	}
	return p
}

// groupsOf returns the group names the claim holds: a list of strings or a
// single one, up to maxGroups of at most maxGroupLen bytes each.
func groupsOf(claims jwt.MapClaims, name string) []string {
	if name == "" {
		return nil
	}
	var values []any
	switch v := claims[name].(type) {
	case []any:
		values = v
	case string:
		values = []any{v}
	}
	var out []string
	for _, v := range values {
		if s, ok := v.(string); ok && s != "" && len(s) <= maxGroupLen && len(out) < maxGroups {
			out = append(out, s)
		}
	}
	return out
}
