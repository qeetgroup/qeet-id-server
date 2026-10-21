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
		"unknown env":              func(c *Config) { c.ServiceEnv = "production" },
		"profile outside local":    func(c *Config) { c.ServiceProfile = "test" },
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

// The hosted login runs passkey sign-in, sign-up and enrolment ceremonies from
// its own origin, so the default origins include it beside the app's.
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

// Local keeps every production gate; it only differs in requiring loopback hosts.
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
		"qa is not a profile":    func(c *Config) { c.ServiceProfile = "qa" },
		"uat is not a profile":   func(c *Config) { c.ServiceProfile = "uat" },
		"stage is not a profile": func(c *Config) { c.ServiceProfile = "stage" },
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

// A process started without SERVICE_ENV doesn't fall back to dev, where the
// production gates are off and a signing key is made up: it refuses to start,
// naming the setting.
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
}

func TestLoad_RejectsUnusableSessionLifetime(t *testing.T) {
	for name, env := range map[string][2]string{
		"maximum age under an hour":           {"SESSION_MAX_AGE", "30m"},
		"maximum age over a year":             {"SESSION_MAX_AGE", "9000h"},
		"idle timeout under 15 minutes":       {"SESSION_IDLE_TIMEOUT", "10m"},
		"idle timeout over the maximum age":   {"SESSION_IDLE_TIMEOUT", "721h"},
		"access tokens outliving idle bounds": {"ACCESS_TOKEN_TTL", "15m"},
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
