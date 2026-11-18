package saml

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

func TestValidIdPSSOURL(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{"https://idp.example.com/sso", true},
		{"https://idp.example.com:8443/app/sso?idpid=abc", true},
		{"HTTPS://IDP.EXAMPLE.COM/sso", true},
		{"http://idp.example.com/sso", false},
		{"http://localhost:8080/sso", false},
		{"https://user:pass@idp.example.com/sso", false},
		{"https://@idp.example.com/sso", false},
		{"https:///sso", false},
		{"https://:443/sso", false},
		{"https:idp.example.com/sso", false},
		{"//idp.example.com/sso", false},
		{"/sso", false},
		{"javascript:alert(1)", false},
		{"https://idp.example.com/\tsso", false},
		{"", false},
	} {
		if got := validIdPSSOURL(c.raw); got != c.want {
			t.Errorf("validIdPSSOURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestServiceRefusesInvalidConnections checks that Service.Create and Update
// apply the SSO URL and certificate checks themselves, for callers other than
// this package's handlers, such as the admin portal.
func TestServiceRefusesInvalidConnections(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	svc, organization := &Service{}, uuid.New()
	ctx := context.Background()
	for _, c := range []struct {
		name string
		in   CreateInput
		want error
	}{
		{"script URL", CreateInput{IdpSSOURL: "javascript:alert(1)", IdpCertificate: pemStr}, ErrSSOURLInvalid},
		{"plain http", CreateInput{IdpSSOURL: "http://idp.example.com/sso", IdpCertificate: pemStr}, ErrSSOURLInvalid},
		{"bad certificate", CreateInput{IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: "not a cert"}, ErrCertificateInvalid},
	} {
		if _, err := svc.Create(ctx, organization, c.in, audit.Actor{}); !errors.Is(err, c.want) {
			t.Errorf("create with %s: %v, want %v", c.name, err, c.want)
		}
	}
	bad, cert := "http://idp.example.com/sso", "not a cert"
	if _, err := svc.Update(ctx, uuid.New(), organization, UpdateInput{IdpSSOURL: &bad}, audit.Actor{}); !errors.Is(err, ErrSSOURLInvalid) {
		t.Errorf("update with plain http: %v", err)
	}
	if _, err := svc.Update(ctx, uuid.New(), organization, UpdateInput{IdpCertificate: &cert}, audit.Actor{}); !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("update with a bad certificate: %v", err)
	}
}
