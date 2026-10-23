package scim

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// FuzzParsePatchBody checks that a SCIM PatchOp body never panics the group
// patch parser or the profile-source builder, and that both return a value.
func FuzzParsePatchBody(f *testing.F) {
	for _, seed := range []string{
		// Okta: targeted member remove, displayName replace.
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` +
			`{"op":"remove","path":"members[value eq \"5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f\"]"},` +
			`{"op":"replace","path":"displayName","value":"Engineering"}]}`,
		// Azure AD: capitalised op, member add as an array.
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` +
			`{"op":"Add","path":"members","value":[{"value":"5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"}]}]}`,
		// Path-less replace with members and attributes.
		`{"Operations":[{"op":"replace","value":{"displayName":"Ops","externalId":"ext-1",` +
			`"members":[{"value":"5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"},{"value":"junk"}]}}]}`,
		`{"Operations":[{"op":"add","value":{"members":[{"value":" 5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f "}]}}]}`,
		`{"Operations":[{"op":"remove","path":"members"}]}`,
		`{"Operations":[{"op":"remove","path":"members","value":null}]}`,
		`{"Operations":[{"op":"remove","path":"members","value":{"value":"5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"}}]}`,
		`{"Operations":[{"op":"add","path":"\"members[value eq 5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f]\""}]}`,
		`{"Operations":[{"op":"add","path":"members[","value":1}]}`,
		`{"Operations":[{"op":"add","path":"members[]]["}]}`,
		`{"Operations":[{"op":"add","path":"members[eq]"}]}`,
		// User attributes, as patchUser and the profile mapper see them.
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"Operations":[{"op":"Replace","value":{"active":false,"displayName":"New Name"}}]}`,
		`{"Operations":[{"op":"replace","path":"name.givenName","value":"Ada"}]}`,
		`{"Operations":[{"op":"replace","path":"a.b.c.d.e.f.g.h.i","value":"too deep"}]}`,
		`{"Operations":[{"op":"replace","path":"a","value":1},{"op":"replace","path":"a.b","value":2}]}`,
		`{"Operations":[{"op":"replace","path":".","value":1},{"op":"replace","path":"a..b","value":2}]}`,
		`{"Operations":[{"op":"add","path":"emails[type eq \"work\"].value","value":"a@example.com"}]}`,
		`{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"R&D"}]}`,
		`{"Operations":[{"op":"remove","path":"name.familyName"}]}`,
		`{"Operations":[{"op":"move","path":"displayName","value":"x"}]}`,
		`{"Operations":[{"op":"replace","path":"displayName","value":{"not":"a string"}}]}`,
		`{"Operations":[{"op":"replace","value":"not an object"}]}`,
		`{"Operations":[{}]}`,
		`{"Operations":null}`,
		`{}`,
		// Multi-byte runes that change length when lowercased.
		"{\"Operations\":[{\"op\":\"remove\",\"path\":\"members[\\u023a\\u023a\\u023aeq]\"}]}",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var body patchBody
		if json.Unmarshal(raw, &body) != nil {
			return
		}
		p, err := parseGroupPatch(body)
		if (p == nil) == (err == nil) {
			t.Fatalf("parseGroupPatch = (%v, %v), want exactly one of patch or error", p, err)
		}
		if patchProfileSource(body) == nil {
			t.Fatal("patchProfileSource returned a nil map")
		}
	})
}

// FuzzMemberIDFromFilterPath checks that the targeted member path parser never
// panics and returns uuid.Nil whenever it reports no match.
func FuzzMemberIDFromFilterPath(f *testing.F) {
	for _, seed := range []string{
		`members[value eq "5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"]`,
		`members[value EQ "5D4BB6A4-8B6E-4C6A-9A8E-0B6F1C2D3E4F"]`,
		`members[value eq 5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f]`,
		`members[value eq "urn:uuid:5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"]`,
		`members[value eq "{5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f}"]`,
		`members[value eq "5d4bb6a48b6e4c6a9a8e0b6f1c2d3e4f"]`,
		`members[value eq "not-a-uuid"]`,
		`members[value eq ""]`,
		`members[value ne "5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"]`,
		`members[eq]`,
		`members[]`,
		`members][`,
		`members[`,
		`members`,
		``,
		`[[[eq "5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"]]]`,
		`members[value eq "5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"].display`,
		// Multi-byte runes and invalid UTF-8 that change length when lowercased.
		"members[ȺȺȺeq]",
		"members[\xff\xff\xffeq]",
		"[\xabeq]",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		id, ok := memberIDFromFilterPath(path)
		if !ok && id != uuid.Nil {
			t.Fatalf("memberIDFromFilterPath(%q) = (%v, false), want uuid.Nil", path, id)
		}
	})
}
