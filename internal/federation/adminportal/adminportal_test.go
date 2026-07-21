package adminportal

import (
	"testing"
	"time"
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

func TestClampTTL(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero defaults", in: 0, want: defaultTTL},
		{name: "negative defaults", in: -time.Hour, want: defaultTTL},
		{name: "below min clamps up", in: time.Minute, want: minTTL},
		{name: "above max clamps down", in: 30 * 24 * time.Hour, want: maxTTL},
		{name: "within range passes through", in: 2 * time.Hour, want: 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampTTL(tc.in); got != tc.want {
				t.Errorf("clampTTL(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLinkHas(t *testing.T) {
	l := Link{Capabilities: []string{"saml"}}
	if !l.Has("saml") {
		t.Error("Has(saml) = false, want true")
	}
	if l.Has("scim") {
		t.Error("Has(scim) = true, want false")
	}
}
