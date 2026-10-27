package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// prodOK is a config that passes all production gates; tests mutate one field
// at a time to assert each gate fires.
func prodOK() *Config {
	return &Config{
		ServiceEnv:                   "prod",
		JWTSecret:                    "a-32-byte-or-longer-random-server-secret",
		JWTSigningKey:                "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
		AccessTokenTTL:               10 * time.Minute,
		JWTSigningKeyRetireGrace:     30 * 24 * time.Hour,
		JWTSigningKeyRefreshInterval: 5 * time.Second,
		SecretsKey:                   "c2VjcmV0cy1rZXktMzItYnl0ZXMtYmFzZTY0LXh4eHg=",
		AllowedOriginsRaw:            "https://app.acme.com",
		AppBaseURL:                   "https://app.acme.com",
		PublicBaseURL:                "https://api.acme.com",
		SMTPHost:                     "smtp.acme.com",
		SMTPFrom:                     "Acme <no-reply@acme.com>",
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
		"csrf disabled":            func(c *Config) { c.CSRFDisabled = true },
		"dev trust headers":        func(c *Config) { c.AuthDevTrustHeaders = true },
		"placeholder secret":       func(c *Config) { c.JWTSecret = "please-change-me-please-change-me" },
		"short secret":             func(c *Config) { c.JWTSecret = "too-short" },
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
		"short secret":           func(c *Config) { c.JWTSecret = "too-short" },
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

// setRequiredEnv provides the variables envconfig requires, so Load errors in
// these tests can only come from the environment contract.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("JWT_SECRET", "a-32-byte-or-longer-random-server-secret")
	t.Setenv("SERVICE_ENV", EnvDev)
}

// TestLoad_RequiresServiceEnv checks that Load fails without SERVICE_ENV,
// naming it, rather than defaulting to dev with its gates off.
func TestLoad_RequiresServiceEnv(t *testing.T) {
	setRequiredEnv(t)
	if err := os.Unsetenv("SERVICE_ENV"); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SERVICE_ENV is not set") {
		t.Fatalf("Load without SERVICE_ENV: err = %v, want one naming SERVICE_ENV", err)
	}
}

func TestLoad_RejectsUnknownEnvironment(t *testing.T) {
	setRequiredEnv(t)
	for _, env := range []string{"staging", "production", "Prod", ""} {
		t.Setenv("SERVICE_ENV", env)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SERVICE_ENV") {
			t.Errorf("SERVICE_ENV=%q: want an environment error, got %v", env, err)
		}
	}
}

func TestLoad_ProfileRequiresLocal(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SERVICE_ENV", EnvDev)
	t.Setenv("SERVICE_PROFILE", "test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SERVICE_PROFILE") {
		t.Fatalf("Load must reject SERVICE_PROFILE outside SERVICE_ENV=local, got %v", err)
	}
	t.Setenv("SERVICE_ENV", EnvLocal)
	c, err := Load()
	if err != nil {
		t.Fatalf("local+test should load: %v", err)
	}
	if c.IsDev() || c.ServiceProfile != "test" {
		t.Errorf("got IsDev=%v profile=%q", c.IsDev(), c.ServiceProfile)
	}
}

func TestLoad_SignInLockoutDefaults(t *testing.T) {
	setRequiredEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("defaults should load: %v", err)
	}
	if c.LoginLockoutThreshold != 5 || c.LoginLockoutWindow != 15*time.Minute || c.LoginLockoutDuration != 15*time.Minute {
		t.Errorf("lockout defaults = %d / %v / %v, want 5 / 15m / 15m",
			c.LoginLockoutThreshold, c.LoginLockoutWindow, c.LoginLockoutDuration)
	}
}

// TestLoad_BreachedPasswordCheckOnByDefault checks that a deployment that
// doesn't set BREACHED_PASSWORD_CHECK checks passwords against known breaches,
// and that setting it false turns the check off.
func TestLoad_BreachedPasswordCheckOnByDefault(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("BREACHED_PASSWORD_CHECK", "")
	if err := os.Unsetenv("BREACHED_PASSWORD_CHECK"); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{EnvProd, EnvLocal} {
		t.Setenv("SERVICE_ENV", env)
		c, err := Load()
		if err != nil {
			t.Fatalf("SERVICE_ENV=%s: defaults should load: %v", env, err)
		}
		if !c.BreachedPasswordCheck {
			t.Errorf("SERVICE_ENV=%s: breached-password check is off by default, want on", env)
		}
	}
	t.Setenv("BREACHED_PASSWORD_CHECK", "false")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.BreachedPasswordCheck {
		t.Error("BREACHED_PASSWORD_CHECK=false left the check on")
	}
}

func TestLoad_RejectsUnsafeSignInLockout(t *testing.T) {
	for name, env := range map[string][2]string{
		"default above its maximum":   {"LOGIN_LOCKOUT_THRESHOLD", "50"},
		"default below its minimum":   {"LOGIN_LOCKOUT_THRESHOLD", "1"},
		"window not whole minutes":    {"LOGIN_LOCKOUT_WINDOW", "90s"},
		"duration above its maximum":  {"LOGIN_LOCKOUT_DURATION", "48h"},
		"minimum threshold zero":      {"LOGIN_LOCKOUT_THRESHOLD_MIN", "0"},
		"account multiplier of one":   {"LOGIN_LOCKOUT_ACCOUNT_MULTIPLIER", "1"},
		"spraying limit of one":       {"LOGIN_SPRAY_ACCOUNTS", "1"},
		"spraying block of no time":   {"LOGIN_SPRAY_BLOCK", "0s"},
		"window maximum below window": {"LOGIN_LOCKOUT_WINDOW_MAX", "10m"},
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(env[0], env[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LOGIN_") {
				t.Errorf("%s=%s: want a lockout configuration error, got %v", env[0], env[1], err)
			}
		})
	}
}

func TestLoad_SessionLifetimeDefaults(t *testing.T) {
	setRequiredEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("defaults should load: %v", err)
	}
	if c.SessionMaxAge != 720*time.Hour || c.SessionIdleTimeout != 24*time.Hour {
		t.Errorf("session defaults = %v / %v, want 720h / 24h", c.SessionMaxAge, c.SessionIdleTimeout)
	}
	if c.RefreshTokenReuseGrace != 30*time.Second {
		t.Errorf("refresh reuse grace default = %v, want 30s", c.RefreshTokenReuseGrace)
	}
	if c.ShutdownTimeout != 20*time.Second || c.ShutdownDrainDelay != 5*time.Second {
		t.Errorf("shutdown defaults = %v / %v, want 20s / 5s", c.ShutdownTimeout, c.ShutdownDrainDelay)
	}
}

func TestLoad_RejectsUnusableSessionLifetime(t *testing.T) {
	for name, env := range map[string][2]string{
		"maximum age under an hour":           {"SESSION_MAX_AGE", "30m"},
		"maximum age over a year":             {"SESSION_MAX_AGE", "9000h"},
		"idle timeout under 15 minutes":       {"SESSION_IDLE_TIMEOUT", "10m"},
		"idle timeout over the maximum age":   {"SESSION_IDLE_TIMEOUT", "721h"},
		"access tokens outliving idle bounds": {"ACCESS_TOKEN_TTL", "15m"},
		"a refresh reuse grace over a minute": {"REFRESH_TOKEN_REUSE_GRACE", "61s"},
		"a negative refresh reuse grace":      {"REFRESH_TOKEN_REUSE_GRACE", "-1s"},
		"a drain delay over 30 seconds":       {"SHUTDOWN_DRAIN_DELAY", "31s"},
		"a drain delay over half the stop":    {"SHUTDOWN_DRAIN_DELAY", "11s"},
		"a shutdown timeout under 5 seconds":  {"SHUTDOWN_TIMEOUT", "4s"},
		"a shutdown timeout over 2 minutes":   {"SHUTDOWN_TIMEOUT", "3m"},
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(env[0], env[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), env[0]) {
				t.Errorf("%s=%s: want a session lifetime error naming it, got %v", env[0], env[1], err)
			}
		})
	}
}
