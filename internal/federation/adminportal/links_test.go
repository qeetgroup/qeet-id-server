package adminportal

import (
	"errors"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestNormalizeCapabilities(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{name: "empty", in: nil, wantErr: true},
		{name: "unknown", in: []string{"ldap"}, wantErr: true},
		{name: "single", in: []string{"saml"}, want: []string{"saml"}},
		{name: "both, mixed case and whitespace", in: []string{" SAML", "scim "}, want: []string{"saml", "scim"}},
		{name: "dedupes", in: []string{"saml", "saml", "scim"}, want: []string{"saml", "scim"}},
		{name: "domain verification", in: []string{"Domain_Verification"}, want: []string{"domain_verification"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCapabilities(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeCapabilities(%v) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCapabilities(%v) unexpected error: %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeCapabilities(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeCapabilities(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestLinkTTL checks that a link lasts as long as asked, an hour when nothing
// is asked, and that a lifetime out of range is refused rather than changed.
func TestLinkTTL(t *testing.T) {
	cases := []struct {
		name    string
		in      time.Duration
		want    time.Duration
		refused bool
	}{
		{name: "none asked defaults", in: 0, want: defaultTTL},
		{name: "the bounds themselves", in: minTTL, want: minTTL},
		{name: "the upper bound", in: maxTTL, want: maxTTL},
		{name: "within range", in: 2 * time.Hour, want: 2 * time.Hour},
		{name: "negative", in: -time.Hour, refused: true},
		{name: "below the minimum", in: time.Minute, refused: true},
		{name: "a week", in: 7 * 24 * time.Hour, refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := linkTTL(tc.in)
			if tc.refused {
				var e *errs.Error
				if !errors.As(err, &e) || e.Code != CodeTTLOutOfRange || e.Metadata["max_seconds"] != 86400 {
					t.Fatalf("linkTTL(%v) = %v, %v; want refused with the bounds", tc.in, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("linkTTL(%v) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
}
