package saml

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestServiceProviderACSURLIsChecked checks the ACS URL rule, and that CreateSP
// and UpdateSP apply it themselves.
func TestServiceProviderACSURLIsChecked(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{"https://sp.example.com/acs", true},
		{"http://localhost:3000/acs", true},
		{"http://127.0.0.1:3000/acs", true},
		{"http://[::1]:3000/acs", true},
		{"http://sp.example.com/acs", false},
		{"https://user@sp.example.com/acs", false},
		{"javascript:alert(1)", false},
		{"/acs", false},
		{"", false},
	} {
		if got := validACSURL(c.raw); got != c.want {
			t.Errorf("validACSURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
	idp, ctx := &IdP{}, context.Background()
	if _, err := idp.createSP(ctx, nil, uuid.New(), CreateSPInput{ACSURL: "http://sp.example.com/acs"}); !errors.Is(err, ErrACSURLInvalid) {
		t.Errorf("CreateSP with plain http: %v", err)
	}
	acs := "javascript:alert(1)"
	if _, err := idp.updateSP(ctx, nil, uuid.New(), uuid.New(), UpdateSPInput{ACSURL: &acs}); !errors.Is(err, ErrACSURLInvalid) {
		t.Errorf("UpdateSP with a script URL: %v", err)
	}
}
