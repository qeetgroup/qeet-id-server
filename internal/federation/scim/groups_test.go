package scim

import (
	"testing"

	"github.com/google/uuid"
)

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
