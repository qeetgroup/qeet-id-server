package adminportal

import (
	"testing"
)

func TestLinkHas(t *testing.T) {
	l := Link{Capabilities: []string{"saml"}}
	if !l.Has("saml") {
		t.Error("Has(saml) = false, want true")
	}
	if l.Has("scim") {
		t.Error("Has(scim) = true, want false")
	}
}
