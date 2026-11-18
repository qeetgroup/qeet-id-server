package saml

import (
	"strings"
	"testing"
)

func testIdP(t *testing.T) *IdP {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatalf("GenerateIdPKeyPEM: %v", err)
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatalf("newIdPSigner: %v", err)
	}
	return &IdP{signer: signer}
}

func TestGenerateIdPKeyPEM(t *testing.T) {
	keyPEM, certPEM, err := GenerateIdPKeyPEM("CN Test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(keyPEM, "PRIVATE KEY") || !strings.Contains(certPEM, "CERTIFICATE") {
		t.Fatal("unexpected PEM block types")
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatalf("newIdPSigner: %v", err)
	}
	if _, err := signer.signingContext(); err != nil {
		t.Fatalf("signingContext: %v", err)
	}
}
