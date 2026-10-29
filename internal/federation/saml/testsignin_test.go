package saml

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
)

// TestTestAttributesAreBounded checks that a test reports the asserted
// attributes by name, with every value, but no more of them, nor longer ones,
// than a report holds.
func TestTestAttributesAreBounded(t *testing.T) {
	values := saml2.Values{}
	for i := range maxTestAttributes + 5 {
		name := "attr-" + strconv.Itoa(1000+i)
		values[name] = samltypes.Attribute{Name: name, Values: []samltypes.AttributeValue{{Value: "v"}}}
	}
	values["attr-0000"] = samltypes.Attribute{
		Name: "attr-0000", FriendlyName: "groups",
		Values: make([]samltypes.AttributeValue, maxTestValues+3),
	}
	values["attr-0000"].Values[0].Value = strings.Repeat("é", maxTestValueBytes)

	got := testAttributes(values)
	if len(got) != maxTestAttributes {
		t.Fatalf("%d attributes reported, want %d", len(got), maxTestAttributes)
	}
	first := got[0]
	if first.Name != "attr-0000" || first.FriendlyName != "groups" || len(first.Values) != maxTestValues || got[1].Name != "attr-1000" {
		t.Errorf("first attributes %+v, %+v; want them by name, values capped", first.Name, got[1].Name)
	}
	if v := first.Values[0]; len(v) > maxTestValueBytes || !utf8.ValidString(v) {
		t.Errorf("a long value reported as %d bytes (valid UTF-8: %v), want at most %d", len(v), utf8.ValidString(v), maxTestValueBytes)
	}
	if got[1].Values == nil || got[1].Values[0] != "v" {
		t.Errorf("values %v, want the one asserted", got[1].Values)
	}
}
