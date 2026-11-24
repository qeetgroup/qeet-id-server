package oidcsso

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
)

const (
	maxGroups   = 200
	maxGroupLen = 256
)

// rulesFor returns the ID token rules of a sign-in through c whose provider
// published doc. A document naming another issuer is refused, unless it is
// a multi-tenant one and c lists the tenants it accepts, or anyone with an
// account at that provider could sign in.
func rulesFor(c *Connection, doc oidcrp.Discovery) (oidcrp.Rules, error) {
	rules := oidcrp.Rules{Issuer: c.Issuer, TenantIDs: c.AllowedIdPTenantIDs, ClientID: c.ClientID}
	switch {
	case oidcrp.IssuerServesTenants(doc.Issuer):
		if len(c.AllowedIdPTenantIDs) == 0 {
			return oidcrp.Rules{}, fmt.Errorf("discovery issuer %q serves every tenant, and the connection lists none", doc.Issuer)
		}
		rules.Issuer, rules.IssuerTemplate = "", doc.Issuer
	case doc.Issuer != c.Issuer:
		return oidcrp.Rules{}, fmt.Errorf("discovery issuer %q is not the connection's %q", doc.Issuer, c.Issuer)
	}
	return rules, nil
}

// profile is what a validated ID token says about the person it signs in.
type profile struct {
	subject        string // the provider's subject, qualified by its issuer
	issuer         string
	email          string // lower-cased
	verified       *bool  // the provider's email_verified; nil when it doesn't say
	name           string // the display name: the name claim, else given and family names
	givenName      string
	familyName     string
	groups         []string
	groupsWithheld bool // the token says nothing of the groups, so memberships stay as they are
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
	}
	p.groups, p.groupsWithheld = groupsOf(claims, c.ClaimMapping.Groups)
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

// groupsOf returns the group names the claim holds (a list of strings or one), up to maxGroups of at
// most maxGroupLen bytes. withheld is true when the connection reads no groups claim or the provider
// left them out for being too many (Microsoft Entra ID's overage: _claim_names or hasgroups).
func groupsOf(claims jwt.MapClaims, name string) (groups []string, withheld bool) {
	if name == "" {
		return nil, true
	}
	if names, ok := claims["_claim_names"].(map[string]any); ok {
		if _, overage := names[name]; overage {
			return nil, true
		}
	}
	if has, ok := claims["hasgroups"].(bool); ok && has && claims[name] == nil {
		return nil, true
	}
	var values []any
	switch v := claims[name].(type) {
	case []any:
		values = v
	case string:
		values = []any{v}
	}
	for _, v := range values {
		if s, ok := v.(string); ok && s != "" && len(s) <= maxGroupLen && len(groups) < maxGroups {
			groups = append(groups, s)
		}
	}
	return groups, false
}
