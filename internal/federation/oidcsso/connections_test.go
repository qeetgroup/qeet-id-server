package oidcsso

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestConnectionInputChecks checks the settings a connection is refused with.
func TestConnectionInputChecks(t *testing.T) {
	policy := egress.PublicPolicy()
	base := func() CreateInput {
		return CreateInput{Name: "Entra", Issuer: "https://login.microsoftonline.com/6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11/v2.0", ClientID: "id", ClientSecret: "secret"}
	}
	in := base()
	if err := in.check(policy); err != nil || len(in.Scopes) != 3 || in.Scopes[0] != "openid" {
		t.Fatalf("a complete connection: %v, scopes %v", err, in.Scopes)
	}
	empty := ""
	for code, change := range map[string]func(*CreateInput){
		CodeFieldsRequired: func(in *CreateInput) { in.ClientSecret = "" },
		CodeIssuerInvalid:  func(in *CreateInput) { in.Issuer = "http://idp.example.test" },
		CodeDiscoveryURLInvalid: func(in *CreateInput) {
			in.DiscoveryURL = "https://idp.example.test/.well-known/openid-configuration#x"
		},
		CodeScopesInvalid:     func(in *CreateInput) { in.Scopes = []string{"email profile"} },
		CodeTenantIDsInvalid:  func(in *CreateInput) { in.AllowedIdPTenantIDs = []string{"contoso"} },
		CodeTenantIDsRequired: func(in *CreateInput) { in.Issuer = "https://login.microsoftonline.com/common/v2.0" },
		CodeClaimInvalid:      func(in *CreateInput) { in.ClaimMapping = &ClaimMappingInput{Email: &empty} },
		CodeStatusInvalid:     func(in *CreateInput) { in.Status = "enabled" },
	} {
		in := base()
		change(&in)
		if err := in.check(policy); errs.As(err) == nil || errs.As(err).Code != code {
			t.Errorf("%s: %v", code, err)
		}
	}
	in = base()
	in.Issuer = "https://login.microsoftonline.com/organizations/v2.0"
	in.AllowedIdPTenantIDs = []string{"6F1C7A52-8C1E-4A43-9A8E-2D6F0B0F5F11", "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11"}
	in.Scopes = []string{"email", "offline_access", "email"}
	if err := in.check(policy); err != nil || len(in.AllowedIdPTenantIDs) != 1 || len(in.Scopes) != 3 {
		t.Errorf("a multi-tenant issuer listing its tenant: %v, %v, %v", err, in.AllowedIdPTenantIDs, in.Scopes)
	}
}
