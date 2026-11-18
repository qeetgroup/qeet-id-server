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

func TestMemberIDFromFilterPath(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name   string
		path   string
		want   uuid.UUID
		wantOK bool
	}{
		{"okta value eq", `members[value eq "` + id.String() + `"]`, id, true},
		{"case-insensitive EQ", `members[VALUE EQ "` + id.String() + `"]`, id, true},
		{"missing bracket", `members value eq "` + id.String() + `"`, uuid.Nil, false},
		{"bad uuid", `members[value eq "nope"]`, uuid.Nil, false},
		{"mixed-case Eq", `members[value Eq "` + id.String() + `"]`, id, true},
		// Multi-byte runes and invalid UTF-8 that change length when lowercased.
		{"multibyte attribute", `members[ȺȺȺ eq "` + id.String() + `"]`, id, true},
		{"invalid utf-8 attribute", "members[\xff\xff eq \"" + id.String() + `"]`, id, true},
		{"multibyte runes before eq", "members[ȺȺȺeq]", uuid.Nil, false},
		{"invalid utf-8 before eq", "members[\xff\xff\xffeq]", uuid.Nil, false},
		{"invalid utf-8 byte before eq", "[\xabeq]", uuid.Nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := memberIDFromFilterPath(c.path)
			if ok != c.wantOK || got != c.want {
				t.Errorf("memberIDFromFilterPath(%q) = (%s, %v), want (%s, %v)", c.path, got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestDecodeMemberRefs(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	// Array form.
	got := decodeMemberRefs(json.RawMessage(`[{"value":"` + a.String() + `"},{"value":"` + b.String() + `"}]`))
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("array form = %v, want [%s %s]", got, a, b)
	}
	// Single-object form (some IdPs).
	got = decodeMemberRefs(json.RawMessage(`{"value":"` + a.String() + `"}`))
	if len(got) != 1 || got[0] != a {
		t.Fatalf("object form = %v, want [%s]", got, a)
	}
	// Junk dropped.
	got = decodeMemberRefs(json.RawMessage(`[{"value":"nope"}]`))
	if len(got) != 0 {
		t.Fatalf("junk should be dropped, got %v", got)
	}
	// Empty.
	if got := decodeMemberRefs(nil); got != nil {
		t.Fatalf("nil raw → nil, got %v", got)
	}
}

// TestParseGroupPatch checks that each PatchOp shape IdPs send for group
// membership resolves to the right effect.
func TestParseGroupPatch(t *testing.T) {
	a, b := uuid.New(), uuid.New()

	mkBody := func(ops string) patchBody {
		var body patchBody
		if err := json.Unmarshal([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":`+ops+`}`), &body); err != nil {
			t.Fatalf("bad test body: %v", err)
		}
		return body
	}

	t.Run("remove externalId", func(t *testing.T) {
		p, err := parseGroupPatch(mkBody(`[{"op":"remove","path":"externalId"}]`))
		if err != nil || p.setExternalID == nil || *p.setExternalID != "" {
			t.Fatalf("got %+v, %v; want externalId cleared", p, err)
		}
	})

	t.Run("remove displayName", func(t *testing.T) {
		if _, err := parseGroupPatch(mkBody(`[{"op":"remove","path":"displayName"}]`)); err == nil {
			t.Fatal("removing the required displayName was accepted")
		}
	})

	t.Run("add members", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"add","path":"members","value":[{"value":"` + a.String() + `"}]}]`))
		if len(p.addMembers) != 1 || p.addMembers[0] != a || p.replaceMembers {
			t.Fatalf("add: got %+v", p)
		}
	})

	t.Run("remove member via value list", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"remove","path":"members","value":[{"value":"` + a.String() + `"}]}]`))
		if len(p.removeMembers) != 1 || p.removeMembers[0] != a {
			t.Fatalf("remove list: got %+v", p)
		}
	})

	t.Run("remove member via okta filter path", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"remove","path":"members[value eq \"` + a.String() + `\"]"}]`))
		if len(p.removeMembers) != 1 || p.removeMembers[0] != a {
			t.Fatalf("remove filter path: got %+v", p)
		}
	})

	t.Run("replace whole member set", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"replace","path":"members","value":[{"value":"` + a.String() + `"},{"value":"` + b.String() + `"}]}]`))
		if !p.replaceMembers || len(p.addMembers) != 2 {
			t.Fatalf("replace members: got %+v", p)
		}
	})

	t.Run("remove all members (no value)", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"remove","path":"members"}]`))
		if !p.replaceMembers || len(p.addMembers) != 0 {
			t.Fatalf("remove all: got %+v", p)
		}
	})

	t.Run("replace displayName", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"replace","path":"displayName","value":"Renamed"}]`))
		if p.setName == nil || *p.setName != "Renamed" {
			t.Fatalf("displayName: got %+v", p)
		}
	})

	t.Run("displayName is trimmed and can't be emptied", func(t *testing.T) {
		p, err := parseGroupPatch(mkBody(`[{"op":"replace","path":"displayName","value":"  Renamed "}]`))
		if err != nil || p.setName == nil || *p.setName != "Renamed" {
			t.Fatalf("padded displayName: got %+v, %v", p, err)
		}
		if p, err := parseGroupPatch(mkBody(`[{"op":"replace","value":{"displayName":"   "}}]`)); err == nil {
			t.Fatalf("blank displayName: got %+v, want an error", p)
		}
	})

	t.Run("path-less replace object", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"replace","value":{"displayName":"X","members":[{"value":"` + a.String() + `"}]}}]`))
		if p.setName == nil || *p.setName != "X" || !p.replaceMembers || len(p.addMembers) != 1 {
			t.Fatalf("path-less replace: got %+v", p)
		}
	})
}
