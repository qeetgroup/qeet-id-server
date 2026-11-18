package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestLocationsUseConfiguredOrigin checks that resource locations are built on
// PublicBaseURL, not on the Host the client sent.
func TestLocationsUseConfiguredOrigin(t *testing.T) {
	handler := &Handler{PublicBaseURL: "https://api.id.qeet.in"}
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	request.Host = "evil.example"
	recorder := httptest.NewRecorder()
	handler.serviceProviderConfig(recorder, request)
	var body struct {
		DocumentationURI string `json:"documentationUri"`
		Meta             struct {
			Location string `json:"location"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.DocumentationURI != "https://api.id.qeet.in/scim/v2" {
		t.Errorf("documentationUri = %q", body.DocumentationURI)
	}
	if body.Meta.Location != "https://api.id.qeet.in/scim/v2/ServiceProviderConfig" {
		t.Errorf("meta.location = %q", body.Meta.Location)
	}
}
