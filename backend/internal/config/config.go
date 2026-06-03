package config

import (
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

	HTTPReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`

	AllowedOriginsRaw   string `envconfig:"ALLOWED_ORIGINS" default:""`
	AuthDevTrustHeaders bool   `envconfig:"AUTH_DEV_TRUST_HEADERS" default:"false"`
	CSRFDisabled        bool   `envconfig:"CSRF_DISABLED" default:"false"`

	// AppBaseURL is the frontend origin used to build links in emails
	// (password reset, magic links, invites).
	AppBaseURL string `envconfig:"APP_BASE_URL" default:"http://localhost:3000"`

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
