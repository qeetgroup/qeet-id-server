package config

import (
	"testing"
)

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

// TestWebAuthnRPDefaultOriginsIncludeHostedLogin checks that the default origins
// include LoginBaseURL beside AppBaseURL, once if they are the same origin, since
// the hosted login runs passkey ceremonies from its own origin.
func TestWebAuthnRPDefaultOriginsIncludeHostedLogin(t *testing.T) {
	c := &Config{ServiceName: "qeet-id", AppBaseURL: "http://localhost:3002", LoginBaseURL: "http://localhost:3003"}
	_, _, origins := c.WebAuthnRP()
	if len(origins) != 2 || origins[0] != "http://localhost:3002" || origins[1] != "http://localhost:3003" {
		t.Errorf("origins = %v, want [http://localhost:3002 http://localhost:3003]", origins)
	}
	// Both on one origin: listed once.
	c.LoginBaseURL = c.AppBaseURL + "/"
	if _, _, origins := c.WebAuthnRP(); len(origins) != 1 {
		t.Errorf("origins = %v, want only http://localhost:3002", origins)
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
