package scim

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// FuzzParseEqualityFilter checks that the SCIM filter parser never panics, and
// that a quoted userName equality filter round-trips to its value.
func FuzzParseEqualityFilter(f *testing.F) {
	for _, seed := range []string{
		``,
		`   `,
		`userName eq "alice@example.com"`,
		`USERNAME EQ "alice@example.com"`,
		`displayName eq "Engineering"`,
		`  userName   eq   "a"  `,
		`userName eq "with \"escaped\" quotes"`,
		`userName eq "back\\slash"`,
		`userName eq "été"`,
		`userName eq "tab\tand\nnewline"`,
		`userName eq "\xff"`,
		`userName eq ""`,
		`userName eq "unterminated`,
		`userName eq "a" and active eq true`,
		`userName eq "a" or userName eq "b"`,
		`userName ne "a"`,
		`userName co "a"`,
		`userName pr`,
		`emails[type eq "work"].value eq "a@example.com"`,
		`name.givenName eq "Ada"`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"`,
		`userName eq 'single'`,
		`userName eq "a"` + "\n",
		"userName eq \"\xc0\xaf\"",
		`1userName eq "a"`,
		`userName eq "\"`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, filter string) {
		blank := strings.TrimSpace(filter) == ""
		for _, parse := range []func(string) (string, error){parseUserNameFilter, parseDisplayNameFilter} {
			value, err := parse(filter)
			switch {
			case err != nil && value != "":
				t.Fatalf("parse(%q) = (%q, %v), want an empty value with the error", filter, value, err)
			case blank && (err != nil || value != ""):
				t.Fatalf("parse(%q) = (%q, %v), want no filter", filter, value, err)
			case !blank && err == nil && value == "":
				t.Fatalf("parse(%q) accepted an empty value", filter)
			}
		}

		if filter == "" {
			return
		}
		quoted := "userName eq " + strconv.Quote(filter)
		got, err := parseUserNameFilter(quoted)
		if err != nil || got != filter {
			t.Fatalf("parseUserNameFilter(%q) = (%q, %v), want %q", quoted, got, err, filter)
		}
	})
}

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
