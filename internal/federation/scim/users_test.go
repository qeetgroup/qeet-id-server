package scim

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzSCIMUserPayload checks that decoding a SCIM User or Group body and reading
// its derived fields never panics, and that the derived email is trimmed.
func FuzzSCIMUserPayload(f *testing.F) {
	for _, seed := range []string{
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com",` +
			`"name":{"givenName":"Alice","familyName":"Smith"},"emails":[{"value":"alice@example.com","primary":true}],` +
			`"displayName":"Alice Smith","externalId":"00u1","active":true}`,
		`{"userName":"  padded@example.com  "}`,
		`{"emails":[{"value":"second@example.com"},{"value":" primary@example.com ","primary":true}]}`,
		`{"emails":[{"value":"","primary":true},{"value":"fallback@example.com"}]}`,
		`{"emails":[]}`,
		`{"name":{"formatted":"Dr. Ada Lovelace"}}`,
		`{"name":null,"emails":null,"active":null}`,
		`{"active":"true"}`,
		`{"userName":123}`,
		`{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"42","manager":{"value":"m"}}}`,
		`{"userName":"a","userName":"b"}`,
		`{"displayName":"Engineering","members":[{"value":"5d4bb6a4-8b6e-4c6a-9a8e-0b6f1c2d3e4f"},{"value":"junk"},{}]}`,
		`{"displayName":"\ud800"}`,
		`null`,
		`[]`,
		`"string"`,
		`{`,
		``,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var user scimUserPayload
		if err := json.Unmarshal(body, &user); err == nil {
			if email := user.email(); email != strings.TrimSpace(email) {
				t.Fatalf("email() = %q, want a trimmed value", email)
			}
			_ = user.display()
			if user.Source == nil && string(bytes.TrimSpace(body)) != "null" {
				t.Fatalf("decoded %q without a Source map", body)
			}
		}
		var group scimGroupPayload
		if json.Unmarshal(body, &group) == nil {
			_ = group.memberIDs()
		}
	})
}

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
