package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ServiceName string `envconfig:"SERVICE_NAME" default:"qeet-identity"`
	ServiceEnv  string `envconfig:"SERVICE_ENV" default:"dev"`
	HTTPPort    string `envconfig:"HTTP_PORT" default:"4000"`
	LogLevel    string `envconfig:"LOG_LEVEL" default:"info"`

	DBURL      string `envconfig:"DB_URL" required:"true"`
	DBMinConns int32  `envconfig:"DB_MIN_CONNS" default:"2"`
	DBMaxConns int32  `envconfig:"DB_MAX_CONNS" default:"10"`

	JWTSecret       string        `envconfig:"JWT_SECRET" required:"true"`
	JWTIssuer       string        `envconfig:"JWT_ISSUER" default:"qeet-identity"`
	JWTAudience     string        `envconfig:"JWT_AUDIENCE" default:"qeet-identity"`
	AccessTokenTTL  time.Duration `envconfig:"ACCESS_TOKEN_TTL" default:"15m"`
	RefreshTokenTTL time.Duration `envconfig:"REFRESH_TOKEN_TTL" default:"720h"`

	// JWTSigningKey is the PEM-encoded EC P-256 private key (PKCS#8 or SEC1)
	// used to sign access & ID tokens with ES256. Empty is allowed only in
	// dev, where an ephemeral key is generated at startup (tokens won't
	// survive a restart). Required outside dev (enforced in config gates).
	JWTSigningKey string `envconfig:"JWT_SIGNING_KEY" default:""`
	// JWTRetiredKeys holds one or more concatenated PEM public keys (SPKI or
	// certificate) of previously-active signing keys. They stay verifiable
	// during the rotation grace window; new tokens are never signed with them.
	JWTRetiredKeys string `envconfig:"JWT_RETIRED_KEYS" default:""`

	// SecretsKey is the base64-encoded AES key (16/24/32 bytes) for the
	// per-tenant secrets vault — independent of JWT_SECRET. Required outside dev
	// (gated); in dev an ephemeral key is generated if unset. Generate with
	// `openssl rand -base64 32`.
	SecretsKey string `envconfig:"SECRETS_KEY" default:""`

	HTTPReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`

	AllowedOriginsRaw   string `envconfig:"ALLOWED_ORIGINS" default:""`
	AuthDevTrustHeaders bool   `envconfig:"AUTH_DEV_TRUST_HEADERS" default:"false"`
	CSRFDisabled        bool   `envconfig:"CSRF_DISABLED" default:"false"`
	// CSRFCookieDomain scopes the CSRF cookie so the double-submit token is
	// readable across sibling subdomains (e.g. ".qeetid.com" lets the hosted
	// login app read a token issued by the API). Empty = host-only.
	CSRFCookieDomain string `envconfig:"CSRF_COOKIE_DOMAIN" default:""`

	// AppBaseURL is the frontend origin used to build links in emails
	// (password reset, magic links, invites).
	AppBaseURL string `envconfig:"APP_BASE_URL" default:"http://localhost:3000"`

	// LoginBaseURL is the origin of the hosted login app (qeetid-login) that
	// the OAuth authorize flow redirects to for sign-in and consent.
	LoginBaseURL string `envconfig:"LOGIN_BASE_URL" default:"http://localhost:3004"`

	// Email (SMTP) — provider-agnostic (Amazon SES, SendGrid, Mailgun, Postmark).
	// Empty SMTPHost leaves email on the log-only fallback (dev).
	SMTPHost     string `envconfig:"SMTP_HOST" default:""`
	SMTPPort     string `envconfig:"SMTP_PORT" default:"587"`
	SMTPUsername string `envconfig:"SMTP_USERNAME" default:""`
	SMTPPassword string `envconfig:"SMTP_PASSWORD" default:""`
	SMTPFrom     string `envconfig:"SMTP_FROM" default:""`

	// SMS (Twilio). Empty credentials leave SMS on the log-only fallback.
	TwilioAccountSID string `envconfig:"TWILIO_ACCOUNT_SID" default:""`
	TwilioAuthToken  string `envconfig:"TWILIO_AUTH_TOKEN" default:""`
	TwilioFrom       string `envconfig:"TWILIO_FROM" default:""`

	// WebAuthn Relying Party config. Empty values default from AppBaseURL /
	// ServiceName (see WebAuthnRP). RP_ID is the effective domain (no scheme/
	// port); RP_ORIGINS is a comma-separated allow-list of full origins.
	WebAuthnRPID          string `envconfig:"WEBAUTHN_RP_ID" default:""`
	WebAuthnRPDisplayName string `envconfig:"WEBAUTHN_RP_DISPLAY_NAME" default:""`
	WebAuthnRPOriginsRaw  string `envconfig:"WEBAUTHN_RP_ORIGINS" default:""`
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate enforces production-safety invariants. Inside SERVICE_ENV=dev it is
// a no-op (dev needs the escape hatches and self-signed defaults); outside dev
// it refuses to start when a dev-only convenience or an insecure default is
// still in place. Failing loudly here is far cheaper than discovering a
// production deploy shipped with CSRF off or a placeholder secret.
func (c *Config) Validate() error {
	if c.ServiceEnv == "dev" {
		return nil
	}
	var problems []string
	if c.CSRFDisabled {
		problems = append(problems, "CSRF_DISABLED must not be set outside dev")
	}
	if c.AuthDevTrustHeaders {
		problems = append(problems, "AUTH_DEV_TRUST_HEADERS must not be set outside dev")
	}
	if isWeakSecret(c.JWTSecret) {
		problems = append(problems, "JWT_SECRET is missing, shorter than 32 chars, or a known placeholder")
	}
	if strings.TrimSpace(c.JWTSigningKey) == "" {
		problems = append(problems, "JWT_SIGNING_KEY is required (PEM EC P-256 private key for ES256 token signing)")
	}
	if strings.TrimSpace(c.SecretsKey) == "" {
		problems = append(problems, "SECRETS_KEY is required (base64 AES key for the secrets vault; `openssl rand -base64 32`)")
	}
	if o := strings.TrimSpace(c.AllowedOriginsRaw); o == "" || o == "*" {
		problems = append(problems, "ALLOWED_ORIGINS must list explicit origins (a wildcard is unsafe with credentialed CORS)")
	}
	if u, err := url.Parse(c.AppBaseURL); err != nil || u.Hostname() == "" || isLocalHost(u.Hostname()) {
		problems = append(problems, "APP_BASE_URL must be a real public origin, not localhost")
	}
	if len(problems) > 0 {
		return fmt.Errorf("insecure configuration for SERVICE_ENV=%q:\n  - %s", c.ServiceEnv, strings.Join(problems, "\n  - "))
	}
	return nil
}

// isWeakSecret flags empty, too-short, or obviously-placeholder secrets.
func isWeakSecret(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 32 {
		return true
	}
	low := strings.ToLower(s)
	for _, bad := range []string{"change-me", "changeme", "please-change", "placeholder", "example", "your-secret"} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	return false
}

func isLocalHost(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".local")
}

func (c *Config) AllowedOrigins() []string {
	if c.AllowedOriginsRaw == "" {
		return []string{"*"}
	}
	parts := strings.Split(c.AllowedOriginsRaw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// WebAuthnRP returns the effective Relying Party config, defaulting the ID to
// the AppBaseURL host, the display name to ServiceName, and the origins to
// AppBaseURL when the explicit env vars are unset.
func (c *Config) WebAuthnRP() (id, displayName string, origins []string) {
	id = c.WebAuthnRPID
	if id == "" {
		if u, err := url.Parse(c.AppBaseURL); err == nil {
			id = u.Hostname()
		}
	}
	displayName = c.WebAuthnRPDisplayName
	if displayName == "" {
		displayName = c.ServiceName
	}
	if c.WebAuthnRPOriginsRaw != "" {
		for _, p := range strings.Split(c.WebAuthnRPOriginsRaw, ",") {
			if t := strings.TrimSpace(p); t != "" {
				origins = append(origins, t)
			}
		}
	} else {
		origins = []string{c.AppBaseURL}
	}
	return id, displayName, origins
}
