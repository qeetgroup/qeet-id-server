package saml

import (
	"slices"
	"testing"

	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
)

// attrs builds the attribute values of an assertion.
func attrs(pairs map[string][]string) saml2.Values {
	values := saml2.Values{}
	for name, vs := range pairs {
		a := samltypes.Attribute{Name: name}
		for _, v := range vs {
			a.Values = append(a.Values, samltypes.AttributeValue{Value: v})
		}
		values[name] = a
	}
	return values
}

// TestAssertedGroups checks that groups come from the connection's attribute,
// else from every common one, and that an Entra ID overage withholds them.
func TestAssertedGroups(t *testing.T) {
	values := attrs(map[string][]string{
		"groups": {"Engineering", "Design"},
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": {"6f1d"},
		"department": {"Payments"},
	})
	if got, withheld := assertedGroups(values, ""); withheld || !slices.Equal(got, []string{"Engineering", "Design", "6f1d"}) {
		t.Errorf("default attributes: %q, withheld %v", got, withheld)
	}
	if got, withheld := assertedGroups(values, "department"); withheld || !slices.Equal(got, []string{"Payments"}) {
		t.Errorf("the connection's attribute: %q, withheld %v", got, withheld)
	}
	if got, withheld := assertedGroups(values, "teams"); withheld || len(got) != 0 {
		t.Errorf("an attribute the assertion lacks: %q, withheld %v; want no groups", got, withheld)
	}
	overage := attrs(map[string][]string{groupsOverage: {"https://graph.microsoft.com/v1.0/users/1/getMemberObjects"}})
	if got, withheld := assertedGroups(overage, ""); !withheld || got != nil {
		t.Errorf("an overage claim: %q, withheld %v; want the groups withheld", got, withheld)
	}
}

// TestAssertedName checks that the display name comes from the connection's
// attribute, else a common display-name attribute, else the given and family
// names.
func TestAssertedName(t *testing.T) {
	for _, c := range []struct {
		name      string
		values    map[string][]string
		attribute string
		want      string
	}{
		{"the connection's attribute", map[string][]string{"name": {" Asha Rao "}, "displayName": {"A. Rao"}}, "name", "Asha Rao"},
		{"a display-name attribute", map[string][]string{"name": {""}, "http://schemas.microsoft.com/identity/claims/displayname": {"Asha Rao"}}, "name", "Asha Rao"},
		{"given and family names", map[string][]string{"givenName": {"Asha"}, "sn": {"Rao"}}, "", "Asha Rao"},
		{"a given name only", map[string][]string{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": {"Asha"}}, "", "Asha"},
		{"none", map[string][]string{"email": {"asha@example.test"}}, "", ""},
	} {
		if got := assertedName(attrs(c.values), c.attribute); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
