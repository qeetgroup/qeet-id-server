package saml

import (
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
)

// The attributes an assertion's groups and names are read from when the
// connection names none: those Microsoft Entra ID, Okta, Google Workspace and
// AD FS commonly send.
var (
	defaultGroupAttributes = []string{"groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "memberOf"}
	displayNameAttributes  = []string{"displayName", "http://schemas.microsoft.com/identity/claims/displayname", "urn:oid:2.16.840.1.113730.3.1.241"}
	givenNameAttributes    = []string{"givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"}
	familyNameAttributes   = []string{"sn", "surname", "lastName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"}
)

// groupsOverage is the claim Microsoft Entra ID sends in place of a person's
// groups when they are in more than an assertion carries.
const groupsOverage = "http://schemas.microsoft.com/claims/groups.link"

// assertedGroups returns the groups an assertion carries in attribute, or in
// the common group attributes when attribute is "". withheld is true when it
// carries none because the IdP left them out, so memberships stay as they are.
func assertedGroups(values saml2.Values, attribute string) (groups []string, withheld bool) {
	names := defaultGroupAttributes
	if attribute != "" {
		names = []string{attribute}
	}
	for _, name := range names {
		groups = append(groups, values.GetAll(name)...)
	}
	if _, overage := values[groupsOverage]; overage && len(groups) == 0 {
		return nil, true
	}
	return groups, false
}

// assertedName returns the person's display name: attribute's value, else a
// common display-name attribute's, else their given and family names joined.
func assertedName(values saml2.Values, attribute string) string {
	if attribute != "" {
		if name := strings.TrimSpace(values.Get(attribute)); name != "" {
			return name
		}
	}
	if name := firstValue(values, displayNameAttributes); name != "" {
		return name
	}
	return strings.TrimSpace(firstValue(values, givenNameAttributes) + " " + firstValue(values, familyNameAttributes))
}

// firstValue returns the first non-empty value of the first of names the
// assertion carries.
func firstValue(values saml2.Values, names []string) string {
	for _, name := range names {
		if v := strings.TrimSpace(values.Get(name)); v != "" {
			return v
		}
	}
	return ""
}
