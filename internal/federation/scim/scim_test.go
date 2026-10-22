package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestParseUserNameFilter(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty", in: "", want: ""},
		{name: "standard okta filter", in: `userName eq "alice@acme.com"`, want: "alice@acme.com"},
		{name: "case-insensitive operator", in: `USERNAME EQ "bob@acme.com"`, want: "bob@acme.com"},
		{name: "extra whitespace", in: `userName eq   "carol@acme.com"  `, want: "carol@acme.com"},
		{"escaped quote", `userName eq "alice\"ops@example.com"`, `alice"ops@example.com`, false},
		{"unsupported attribute", `emails.value eq "x@acme.com"`, "", true},
		{"unsupported operator", `userName co "acme"`, "", true},
		{"missing quotes", `userName eq alice@acme.com`, "", true},
		{"boolean expression", `userName eq "a" or userName eq "b"`, "", true},
		{"empty value", `userName eq ""`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseUserNameFilter(c.in)
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("parseUserNameFilter(%q) = (%q, %v), want (%q, err=%v)", c.in, got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestStatusFromActive(t *testing.T) {
	tru, fls := true, false
	if got := statusFromActive(nil); got != "" {
		t.Errorf("nil active should leave status untouched, got %q", got)
	}
	if got := statusFromActive(&tru); got != "active" {
		t.Errorf("active=true → active, got %q", got)
	}
	if got := statusFromActive(&fls); got != "suspended" {
		t.Errorf("active=false → suspended, got %q", got)
	}
}

func TestScimUserPayload_Email(t *testing.T) {
	// userName wins.
	p := scimUserPayload{UserName: "  alice@acme.com  ", Emails: []scimEmail{{Value: "other@acme.com", Primary: true}}}
	if got := p.email(); got != "alice@acme.com" {
		t.Errorf("userName should win and be trimmed, got %q", got)
	}
	// Falls back to primary email.
	p = scimUserPayload{Emails: []scimEmail{{Value: "sec@acme.com"}, {Value: "prim@acme.com", Primary: true}}}
	if got := p.email(); got != "prim@acme.com" {
		t.Errorf("primary email fallback, got %q", got)
	}
	// Falls back to first email when none primary.
	p = scimUserPayload{Emails: []scimEmail{{Value: "first@acme.com"}}}
	if got := p.email(); got != "first@acme.com" {
		t.Errorf("first email fallback, got %q", got)
	}
	// Nothing usable.
	if got := (scimUserPayload{}).email(); got != "" {
		t.Errorf("no email → empty, got %q", got)
	}
}

func TestScimUserPayload_Display(t *testing.T) {
	if got := (scimUserPayload{DisplayName: "Alice A"}).display(); got != "Alice A" {
		t.Errorf("displayName wins, got %q", got)
	}
	if got := (scimUserPayload{Name: &scimName{Formatted: "Bob B"}}).display(); got != "Bob B" {
		t.Errorf("name.formatted fallback, got %q", got)
	}
	if got := (scimUserPayload{Name: &scimName{GivenName: "Carol", FamilyName: "C"}}).display(); got != "Carol C" {
		t.Errorf("given+family fallback, got %q", got)
	}
	if got := (scimUserPayload{}).display(); got != "" {
		t.Errorf("no name → empty, got %q", got)
	}
}

func TestParseDisplayNameFilter(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty", in: "", want: ""},
		{name: "standard okta filter", in: `displayName eq "Engineering"`, want: "Engineering"},
		{name: "case-insensitive operator", in: `DISPLAYNAME EQ "Sales"`, want: "Sales"},
		{name: "extra whitespace", in: `displayName eq   "Ops Team"  `, want: "Ops Team"},
		{"unsupported attribute", `id eq "x"`, "", true},
		{"unsupported operator", `displayName co "Eng"`, "", true},
		{"missing closing quote", `displayName eq "Engineering`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDisplayNameFilter(c.in)
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("parseDisplayNameFilter(%q) = (%q, %v), want (%q, err=%v)", c.in, got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestUnsupportedFiltersReturnSCIMInvalidFilter(t *testing.T) {
	handler := &Handler{}
	for _, test := range []struct {
		name string
		path string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "users", path: `/scim/v2/Users?filter=emails.value+eq+%22x%40example.com%22`, call: handler.listUsers},
		{name: "groups", path: `/scim/v2/Groups?filter=displayName+co+%22Eng%22`, call: handler.listGroups},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request = request.WithContext(context.WithValue(request.Context(), tenantCtxKey, uuid.New()))
			recorder := httptest.NewRecorder()
			test.call(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode SCIM error: %v", err)
			}
			if body["scimType"] != "invalidFilter" {
				t.Fatalf("scimType = %v, want invalidFilter", body["scimType"])
			}
		})
	}
}

func TestScimGroupPayload_MemberIDs(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	p := scimGroupPayload{Members: []scimGroupMemberRef{
		{Value: "  " + a.String() + "  "}, // trimmed
		{Value: "not-a-uuid"},             // dropped
		{Value: b.String()},
	}}
	got := p.memberIDs()
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("memberIDs() = %v, want [%s %s]", got, a, b)
	}
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

	t.Run("path-less replace object", func(t *testing.T) {
		p, _ := parseGroupPatch(mkBody(`[{"op":"replace","value":{"displayName":"X","members":[{"value":"` + a.String() + `"}]}}]`))
		if p.setName == nil || *p.setName != "X" || !p.replaceMembers || len(p.addMembers) != 1 {
			t.Fatalf("path-less replace: got %+v", p)
		}
	})
}
