package saml

import (
	"testing"
)

func TestParseCertificate(t *testing.T) {
	pemStr, b64DER := selfSignedCert(t)

	if _, err := parseCertificate(pemStr); err != nil {
		t.Errorf("PEM cert should parse: %v", err)
	}
	if _, err := parseCertificate(b64DER); err != nil {
		t.Errorf("bare base64 DER should parse: %v", err)
	}
	// base64 DER with copy-paste whitespace (IdP metadata is often wrapped).
	wrapped := b64DER[:40] + "\n  " + b64DER[40:]
	if _, err := parseCertificate(wrapped); err != nil {
		t.Errorf("whitespace-wrapped base64 DER should parse: %v", err)
	}
	if _, err := parseCertificate("not-a-cert"); err == nil {
		t.Error("garbage input should fail")
	}
	if _, err := parseCertificate("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----"); err == nil {
		t.Error("malformed PEM should fail")
	}
}
