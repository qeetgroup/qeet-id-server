package oidcsso

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
)

// TestRulesForTenants checks that a provider serving many tenants is
// accepted only for a connection listing the tenants it signs in, and that a
// discovery document naming another issuer is refused.
func TestRulesForTenants(t *testing.T) {
	const mine = "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11"
	template := "https://login.example.test/{tenantid}/v2.0"
	conn := &Connection{Issuer: "https://login.example.test/organizations/v2.0", ClientID: "qeet-client"}
	if _, err := rulesFor(conn, oidcrp.Discovery{Issuer: template}); err == nil {
		t.Error("a multi-tenant provider was accepted for a connection listing no tenants")
	}
	conn.AllowedIdPTenantIDs = []string{mine}
	if got, err := rulesFor(conn, oidcrp.Discovery{Issuer: template}); err != nil || got.IssuerTemplate != template ||
		got.Issuer != "" || len(got.TenantIDs) != 1 || got.ClientID != "qeet-client" {
		t.Errorf("a multi-tenant provider for a connection listing its tenants: %+v, %v", got, err)
	}
	if _, err := rulesFor(&Connection{Issuer: "https://idp.example.test"}, oidcrp.Discovery{Issuer: "https://other.example.test"}); err == nil {
		t.Error("a discovery document naming another issuer was accepted")
	}
	if got, err := rulesFor(&Connection{Issuer: "https://idp.example.test", ClientID: "c"}, oidcrp.Discovery{Issuer: "https://idp.example.test"}); err != nil || got.Issuer != "https://idp.example.test" {
		t.Errorf("the connection's own issuer: %+v, %v", got, err)
	}
}

// TestProfileOf checks which claims a sign-in reads, and that email_verified
// speaks only for the email claim.
func TestProfileOf(t *testing.T) {
	conn := &Connection{ClaimMapping: ClaimMapping{Email: "email", Name: "name", GivenName: "given_name", FamilyName: "family_name", Groups: "groups"}}
	p := conn.profileOf(jwt.MapClaims{
		"iss": "https://idp.example.test", "sub": "u-1", "email": " Asha@Example.Test ", "email_verified": "false",
		"given_name": "Asha", "family_name": "Rao", "groups": []any{"eng", 7, "ops"},
	})
	if p.subject != "https://idp.example.test#u-1" || p.email != "asha@example.test" || p.name != "Asha Rao" ||
		p.verified == nil || *p.verified || len(p.groups) != 2 || p.groupsWithheld {
		t.Errorf("profile %+v", p)
	}
	if p := conn.profileOf(jwt.MapClaims{"sub": "u-1"}); len(p.groups) != 0 || p.groupsWithheld {
		t.Errorf("a token without the groups claim: %+v, want no groups", p)
	}
	for name, claims := range map[string]jwt.MapClaims{
		"too many groups (_claim_names)": {"_claim_names": map[string]any{"groups": "src1"}},
		"too many groups (hasgroups)":    {"hasgroups": true},
	} {
		if p := conn.profileOf(claims); !p.groupsWithheld {
			t.Errorf("%s: %+v, want the groups withheld", name, p)
		}
	}
	unmapped := *conn
	unmapped.ClaimMapping.Groups = ""
	if p := unmapped.profileOf(jwt.MapClaims{"groups": []any{"eng"}}); !p.groupsWithheld || len(p.groups) != 0 {
		t.Errorf("a connection reading no groups claim: %+v, want the groups withheld", p)
	}
	if p := conn.profileOf(jwt.MapClaims{"email": "asha@example.test"}); p.verified != nil {
		t.Errorf("a token that doesn't say: verified %v, want unknown", *p.verified)
	}
	conn.ClaimMapping.Email = "upn"
	if p := conn.profileOf(jwt.MapClaims{"upn": "asha@example.test", "email_verified": false}); p.email != "asha@example.test" || p.verified != nil {
		t.Errorf("email read from upn: %+v; want email_verified ignored", p)
	}
}
