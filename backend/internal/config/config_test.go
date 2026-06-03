package config

import "testing"

// prodOK is a config that passes all production gates; tests mutate one field
// at a time to assert each gate fires.
func prodOK() *Config {
	return &Config{
		ServiceEnv:        "prod",
		JWTSecret:         "a-32-byte-or-longer-random-server-secret",
		JWTSigningKey:     "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
		SecretsKey:        "c2VjcmV0cy1rZXktMzItYnl0ZXMtYmFzZTY0LXh4eHg=",
		AllowedOriginsRaw: "https://app.acme.com",
		AppBaseURL:        "https://app.acme.com",
	}
}

func TestValidate_DevSkipsAllGates(t *testing.T) {
	c := &Config{ServiceEnv: "dev", CSRFDisabled: true, AuthDevTrustHeaders: true}
	if err := c.Validate(); err != nil {
		t.Errorf("dev must skip gates, got: %v", err)
	}
}

func TestValidate_ProdHappyPath(t *testing.T) {
	if err := prodOK().Validate(); err != nil {
		t.Errorf("valid prod config should pass: %v", err)
	}
}

func TestValidate_ProdRejectsInsecure(t *testing.T) {
	cases := map[string]func(*Config){
		"csrf disabled":       func(c *Config) { c.CSRFDisabled = true },
		"dev trust headers":   func(c *Config) { c.AuthDevTrustHeaders = true },
		"placeholder secret":  func(c *Config) { c.JWTSecret = "please-change-me-please-change-me" },
		"short secret":        func(c *Config) { c.JWTSecret = "too-short" },
		"missing signing key": func(c *Config) { c.JWTSigningKey = "" },
		"missing secrets key": func(c *Config) { c.SecretsKey = "" },
		"wildcard origins":    func(c *Config) { c.AllowedOriginsRaw = "*" },
		"empty origins":       func(c *Config) { c.AllowedOriginsRaw = "" },
		"localhost base url":  func(c *Config) { c.AppBaseURL = "http://localhost:3000" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := prodOK()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected %q to fail validation", name)
			}
		})
	}
}

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
