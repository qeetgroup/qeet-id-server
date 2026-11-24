package config

import (
	"strings"
	"testing"
	"time"
)

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
		"csrf disabled":            func(c *Config) { c.CSRFDisabled = true },
		"dev trust headers":        func(c *Config) { c.AuthDevTrustHeaders = true },
		"placeholder relay key":    func(c *Config) { c.RelayKeysRaw = "please-change-me-please-change-me" },
		"short relay key":          func(c *Config) { c.RelayKeysRaw = "a-32-byte-or-longer-relay-key-000,too-short" },
		"missing signing key":      func(c *Config) { c.JWTSigningKey = "" },
		"short signing key grace":  func(c *Config) { c.JWTSigningKeyRetireGrace = time.Minute },
		"zero signing key refresh": func(c *Config) { c.JWTSigningKeyRefreshInterval = 0 },
		"missing secrets key":      func(c *Config) { c.SecretsKey = "" },
		"wildcard origins":         func(c *Config) { c.AllowedOriginsRaw = "*" },
		"empty origins":            func(c *Config) { c.AllowedOriginsRaw = "" },
		"localhost base url":       func(c *Config) { c.AppBaseURL = "http://localhost:3000" },
		"*.localhost base url":     func(c *Config) { c.AppBaseURL = "http://console.test.id.qeet.localhost" },
		"kit zone base url":        func(c *Config) { c.AppBaseURL = "https://console.test.id.qeet.in" },
		"unknown env":              func(c *Config) { c.ServiceEnv = "production" },
		"profile outside local":    func(c *Config) { c.ServiceProfile = "test" },
		"missing public base url":  func(c *Config) { c.PublicBaseURL = "" },
		"http public base url":     func(c *Config) { c.PublicBaseURL = "http://api.acme.com" },
		"public base url path":     func(c *Config) { c.PublicBaseURL = "https://api.acme.com/v1" },
		"public base url userinfo": func(c *Config) { c.PublicBaseURL = "https://user@api.acme.com" },
		"public base url query":    func(c *Config) { c.PublicBaseURL = "https://api.acme.com?" },
		"public base url fragment": func(c *Config) { c.PublicBaseURL = "https://api.acme.com#" },
		"public base url no host":  func(c *Config) { c.PublicBaseURL = "https://:443" },
		"no email provider":        func(c *Config) { c.SMTPHost = "" },
		"smtp without a sender":    func(c *Config) { c.SMTPFrom = "" },
		"ses without a sender":     func(c *Config) { c.EmailProvider, c.AWSRegion, c.SMTPFrom = "ses-api", "ap-south-2", "" },
		"ses without a region":     func(c *Config) { c.EmailProvider = "ses-api" },
		"unknown email provider":   func(c *Config) { c.EmailProvider = "sendgrid" },
		"default issuer":           func(c *Config) { c.JWTIssuer = "qeet-id" },
		"http issuer":              func(c *Config) { c.JWTIssuer = "http://api.acme.com" },
		"issuer without host":      func(c *Config) { c.JWTIssuer = "https://" },
		"issuer with query":        func(c *Config) { c.JWTIssuer = "https://api.acme.com?tenant=1" },
		"issuer with fragment":     func(c *Config) { c.JWTIssuer = "https://api.acme.com#x" },
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

// TestValidate_EmailProvider checks that outside dev either email provider is
// accepted once configured, and that dev starts with none.
func TestValidate_EmailProvider(t *testing.T) {
	c := prodOK()
	c.EmailProvider = "smtp"
	if err := c.Validate(); err != nil {
		t.Errorf("smtp provider should pass: %v", err)
	}
	c = prodOK()
	c.EmailProvider, c.SMTPHost, c.AWSRegion = "ses-api", "", "ap-south-2"
	if err := c.Validate(); err != nil {
		t.Errorf("ses-api provider should pass: %v", err)
	}
	c = prodOK()
	c.SMTPHost = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "email provider") {
		t.Errorf("prod without an email provider: err = %v, want one naming the email provider", err)
	}
	dev := &Config{ServiceEnv: EnvDev, EmailProvider: "smtp"}
	if err := dev.Validate(); err != nil {
		t.Errorf("dev must start without an email provider, got: %v", err)
	}
}

func TestValidate_LocalHappyPath(t *testing.T) {
	for _, profile := range []string{"dev", "test", "staging"} {
		c := localOK()
		c.ServiceProfile = profile
		if err := c.Validate(); err != nil {
			t.Errorf("valid local %s config should pass: %v", profile, err)
		}
	}
	c := localOK()
	c.ServiceProfile = ""
	if err := c.Validate(); err != nil {
		t.Errorf("local without a profile should pass: %v", err)
	}
}

// TestValidate_LocalAcceptsItsKitZoneOverHTTPS checks that a local runtime may
// use https hosts on its own profile's kit zone (<profile>.id.qeet.in).
func TestValidate_LocalAcceptsItsKitZoneOverHTTPS(t *testing.T) {
	for _, profile := range []string{"dev", "test", "staging"} {
		c := localOK()
		c.ServiceProfile = profile
		c.AllowedOriginsRaw = "https://login." + profile + ".id.qeet.in,https://console." + profile + ".id.qeet.in"
		c.AppBaseURL = "https://console." + profile + ".id.qeet.in"
		c.LoginBaseURL = "https://login." + profile + ".id.qeet.in"
		if err := c.Validate(); err != nil {
			t.Errorf("local %s on its kit zone should pass: %v", profile, err)
		}
	}
}

// TestValidate_LocalRejectsInsecureAndPublicHosts checks that local keeps every
// production gate and refuses public hosts, its kit zone over http, another
// profile's zone, lookalike hosts and unknown profiles.
func TestValidate_LocalRejectsInsecureAndPublicHosts(t *testing.T) {
	cases := map[string]func(*Config){
		"csrf disabled":          func(c *Config) { c.CSRFDisabled = true },
		"dev trust headers":      func(c *Config) { c.AuthDevTrustHeaders = true },
		"payment sandbox":        func(c *Config) { c.PaymentSandbox = true },
		"short relay key":        func(c *Config) { c.RelayKeysRaw = "too-short" },
		"missing signing key":    func(c *Config) { c.JWTSigningKey = "" },
		"missing secrets key":    func(c *Config) { c.SecretsKey = "" },
		"wildcard origins":       func(c *Config) { c.AllowedOriginsRaw = "*" },
		"public app base url":    func(c *Config) { c.AppBaseURL = "https://console.id.qeet.in" },
		"public login url":       func(c *Config) { c.LoginBaseURL = "https://login.id.qeet.in" },
		"lookalike login host":   func(c *Config) { c.LoginBaseURL = "http://login.localhost.example.com" },
		"kit zone over http":     func(c *Config) { c.AppBaseURL = "http://console.test.id.qeet.in" },
		"another profile's zone": func(c *Config) { c.AppBaseURL = "https://console.staging.id.qeet.in" },
		"kit zone lookalike":     func(c *Config) { c.LoginBaseURL = "https://login.test.id.qeet.in.example.com" },
		"kit zone prefix lookalike": func(c *Config) {
			c.LoginBaseURL = "https://login.evil-test.id.qeet.in"
		},
		"production zone apex": func(c *Config) { c.AppBaseURL = "https://id.qeet.in" },
		"kit zone without a profile": func(c *Config) {
			c.ServiceProfile = ""
			c.AppBaseURL = "https://console.test.id.qeet.in"
		},
		"qa is not a profile":    func(c *Config) { c.ServiceProfile = "qa" },
		"uat is not a profile":   func(c *Config) { c.ServiceProfile = "uat" },
		"stage is not a profile": func(c *Config) { c.ServiceProfile = "stage" },
		"no email provider":      func(c *Config) { c.SMTPHost = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := localOK()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected %q to fail validation", name)
			}
		})
	}
}

// TestValidate_ListsEveryProblemInOrder pins the whole refusal of a
// production config with every gate failing at once: each problem, worded as
// an operator reads it, in the order Validate checks them.
func TestValidate_ListsEveryProblemInOrder(t *testing.T) {
	c := &Config{
		ServiceEnv:          "prod",
		CSRFDisabled:        true,
		AuthDevTrustHeaders: true,
		PaymentSandbox:      true,
		AccessTokenTTL:      10 * time.Minute,
		EgressProxyURL:      "not a url",
		SecretsProvider:     "aws-kms",
		RelayKeysRaw:        "short",
		EmailProvider:       "ses-api",
		AllowedOriginsRaw:   "*",
		PublicBaseURL:       "http://api.acme.com/v1",
		AppBaseURL:          "http://localhost:3000",
		JWTIssuer:           "qeet-id",
		QeetaiProvider:      "anthropic",
	}
	want := `insecure configuration for SERVICE_ENV="prod":
  - CSRF_DISABLED must not be set outside dev
  - AUTH_DEV_TRUST_HEADERS must not be set outside dev
  - PAYMENT_SANDBOX must not be set outside dev (it takes payments without charging)
  - JWT_SIGNING_KEY is required (a PEM private key: EC P-256 to sign ES256, or RSA to sign RS256)
  - JWT_SIGNING_KEY_RETIRE_GRACE must cover ACCESS_TOKEN_TTL and be at least 1h
  - JWT_SIGNING_KEY_REFRESH_INTERVAL must be positive
  - EGRESS_PROXY_URL must be an absolute URL with a host
  - KMS_KEY_ID is required with SECRETS_PROVIDER=aws-kms (the KMS key ARN/id)
  - SECRETS_WRAPPED_DEK is required with SECRETS_PROVIDER=aws-kms (base64 KMS CiphertextBlob of the wrapped data key)
  - RELAY_KEYS: every key must be at least 32 characters and not a placeholder (` + "`openssl rand -base64 32`" + `)
  - SMTP_FROM and AWS_REGION are required with EMAIL_PROVIDER=ses-api
  - ALLOWED_ORIGINS must list explicit origins (a wildcard is unsafe with credentialed CORS)
  - PUBLIC_BASE_URL must be an origin such as https://api.example.com (https in prod)
  - APP_BASE_URL must be a real public origin, not localhost or a kit zone
  - JWT_ISSUER must be an https URL with no query or fragment, such as https://api.example.com (OpenID Connect discovery requires it; the default qeet-id is for development)
  - QEETAI_API_KEY is required when QEETAI_PROVIDER is set`
	if err := c.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate() = %v\nwant %s", err, want)
	}

	local := &Config{ServiceEnv: "local", ServiceProfile: "test", SecretsKey: "k", SMTPHost: "smtp", SMTPFrom: "f",
		AllowedOriginsRaw: "https://console.test.id.qeet.in", JWTSigningKey: "k", AccessTokenTTL: time.Minute,
		JWTSigningKeyRetireGrace: time.Hour, JWTSigningKeyRefreshInterval: time.Second,
		AppBaseURL: "http://console.test.id.qeet.in", LoginBaseURL: "https://login.example.com"}
	want = `insecure configuration for SERVICE_ENV="local":
  - APP_BASE_URL must use https on the test.id.qeet.in kit zone
  - LOGIN_BASE_URL must use localhost, a *.localhost host or https on this profile's kit zone (<profile>.id.qeet.in) with SERVICE_ENV=local`
	if err := local.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate() of a local config = %v\nwant %s", err, want)
	}
}

// prodOK is a config that passes all production gates; tests mutate one field
// at a time to assert each gate fires.
func prodOK() *Config {
	return &Config{
		ServiceEnv:                   "prod",
		JWTSigningKey:                "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
		AccessTokenTTL:               10 * time.Minute,
		JWTSigningKeyRetireGrace:     30 * 24 * time.Hour,
		JWTSigningKeyRefreshInterval: 5 * time.Second,
		SecretsKey:                   "c2VjcmV0cy1rZXktMzItYnl0ZXMtYmFzZTY0LXh4eHg=",
		AllowedOriginsRaw:            "https://app.acme.com",
		AppBaseURL:                   "https://app.acme.com",
		PublicBaseURL:                "https://api.acme.com",
		JWTIssuer:                    "https://api.acme.com",
		SMTPHost:                     "smtp.acme.com",
		SMTPFrom:                     "Acme <no-reply@acme.com>",
	}
}

// localOK is the Local-tier test-kit shape: every production gate satisfied,
// browser-facing hosts on *.localhost.
func localOK() *Config {
	c := prodOK()
	c.ServiceEnv = EnvLocal
	c.ServiceProfile = "test"
	c.AllowedOriginsRaw = "http://login.test.id.qeet.localhost,http://console.test.id.qeet.localhost"
	c.AppBaseURL = "http://console.test.id.qeet.localhost"
	c.LoginBaseURL = "http://login.test.id.qeet.localhost"
	return c
}
