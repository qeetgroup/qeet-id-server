package scim

import "testing"

func TestParseUserNameFilter(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"standard okta filter", `userName eq "alice@acme.com"`, "alice@acme.com"},
		{"case-insensitive operator", `USERNAME EQ "bob@acme.com"`, "bob@acme.com"},
		{"extra whitespace", `userName eq   "carol@acme.com"  `, "carol@acme.com"},
		{"unsupported attribute returns all", `emails.value eq "x@acme.com"`, ""},
		{"unsupported operator returns all", `userName co "acme"`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseUserNameFilter(c.in); got != c.want {
				t.Errorf("parseUserNameFilter(%q) = %q, want %q", c.in, got, c.want)
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
