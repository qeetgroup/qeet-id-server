package config

import "testing"

func TestWebAuthnRPDefaults(t *testing.T) {
	c := &Config{ServiceName: "qeet-id", AppBaseURL: "http://localhost:3000"}
	id, dn, origins := c.WebAuthnRP()
	if id != "localhost" {
		t.Errorf("rp id = %q, want localhost", id)
	}
	if dn != "qeet-id" {
		t.Errorf("display name = %q, want qeet-id", dn)
	}
	if len(origins) != 1 || origins[0] != "http://localhost:3000" {
		t.Errorf("origins = %v, want [http://localhost:3000]", origins)
	}
}

func TestWebAuthnRPExplicit(t *testing.T) {
	c := &Config{
		ServiceName:           "qeet-id",
		AppBaseURL:            "http://localhost:3000",
		WebAuthnRPID:          "auth.acme.com",
		WebAuthnRPDisplayName: "Acme",
		WebAuthnRPOriginsRaw:  "https://app.acme.com, https://admin.acme.com",
	}
	id, dn, origins := c.WebAuthnRP()
	if id != "auth.acme.com" || dn != "Acme" {
		t.Errorf("id/dn = %q/%q, want auth.acme.com/Acme", id, dn)
	}
	if len(origins) != 2 || origins[0] != "https://app.acme.com" || origins[1] != "https://admin.acme.com" {
		t.Errorf("origins = %v, want [https://app.acme.com https://admin.acme.com]", origins)
	}
}
