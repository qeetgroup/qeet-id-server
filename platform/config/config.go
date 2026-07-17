package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/qeetgroup/qeet-id/platform/observability/tracing"
)

type Config struct {
	ServiceName string `envconfig:"SERVICE_NAME" default:"qeet-id"`
	ServiceEnv  string `envconfig:"SERVICE_ENV" default:"dev"`
	HTTPPort    string `envconfig:"HTTP_PORT" default:"4001"`
	LogLevel    string `envconfig:"LOG_LEVEL" default:"info"`

	// OTelEndpoint is the OTLP/HTTP collector endpoint for distributed tracing
	// (e.g. http://otel-collector:4318). Empty disables tracing entirely — no
	// exporter is built and nothing connects anywhere (a no-op tracer is used),
	// so the app boots and tests run without a collector present.
	OTelEndpoint string `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT" default:""`
	// OTelSampleRatio is the head sampling ratio for root spans (0..1). 1 keeps
	// every trace (sensible in dev); lower it in prod to bound export volume.
	OTelSampleRatio float64 `envconfig:"OTEL_TRACES_SAMPLER_RATIO" default:"1"`

	DBURL      string `envconfig:"DB_URL" required:"true"`
	DBMinConns int32  `envconfig:"DB_MIN_CONNS" default:"2"`
	DBMaxConns int32  `envconfig:"DB_MAX_CONNS" default:"10"`
	// DBMigrateURL, when set, is used to run migrations (and only migrations)
	// instead of DB_URL. Point it at an owner/superuser role when DB_URL is a
	// dedicated least-privilege application role that is subject to Row-Level
	// Security and cannot run DDL. Empty (default) = run migrations as DB_URL,
	// preserving the single-role setup.
	DBMigrateURL string `envconfig:"DB_MIGRATE_URL"`

	JWTSecret   string `envconfig:"JWT_SECRET" required:"true"`
	JWTIssuer   string `envconfig:"JWT_ISSUER" default:"qeet-id"`
	JWTAudience string `envconfig:"JWT_AUDIENCE" default:"qeet-id"`
	// AccessTokenTTL bounds how long a revoked-but-not-yet-expired access
	// token stays usable: access tokens are stateless JWTs, verified by
	// signature alone on every request (no per-request DB revocation check),
	// so this TTL is the hard ceiling on that exposure window. 10m — down
	// from 15m — is a modest, low-risk trim; the real mitigation is the
	// session.revoked/token.claims_change webhook signals (see
	// domains/access/authentication and domains/access/authorization/rbac)
	// that let a relying party react immediately instead of waiting out
	// whatever this is set to.
	AccessTokenTTL  time.Duration `envconfig:"ACCESS_TOKEN_TTL" default:"10m"`
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

	// SAMLIdPKey / SAMLIdPCert are the RSA private key + X.509 certificate (PEM)
	// used to sign issued SAML assertions when Qeet acts as an IdP (an SSO
	// source). Empty in dev → an ephemeral self-signed cert is generated at boot
	// (SPs must re-import metadata after a restart). Set both in prod so the IdP
	// metadata/cert stay stable across restarts.
	SAMLIdPKey  string `envconfig:"SAML_IDP_KEY" default:""`
	SAMLIdPCert string `envconfig:"SAML_IDP_CERT" default:""`

	// SecretsKey is the base64-encoded AES key (16/24/32 bytes) for the
	// per-tenant secrets vault — independent of JWT_SECRET. Required outside dev
	// when SECRETS_PROVIDER=static; in dev an ephemeral key is generated if
	// unset. Generate with `openssl rand -base64 32`.
	SecretsKey string `envconfig:"SECRETS_KEY" default:""`

	// SecretsProvider selects how the vault data-encryption key is sourced:
	//   static  — from SECRETS_KEY (default)
	//   aws-kms — unwrapped at boot from KMS_KEY_ID + SECRETS_WRAPPED_DEK
	SecretsProvider string `envconfig:"SECRETS_PROVIDER" default:"static"`
	// KMSKeyID is the AWS KMS key ARN/id used to unwrap the DEK (aws-kms only).
	KMSKeyID string `envconfig:"KMS_KEY_ID" default:""`
	// SecretsWrappedDEK is the base64 KMS CiphertextBlob of the wrapped data key
	// (output of `aws kms generate-data-key`), unwrapped at boot (aws-kms only).
	SecretsWrappedDEK string `envconfig:"SECRETS_WRAPPED_DEK" default:""`

	HTTPReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`

	AllowedOriginsRaw   string `envconfig:"ALLOWED_ORIGINS" default:""`
	AuthDevTrustHeaders bool   `envconfig:"AUTH_DEV_TRUST_HEADERS" default:"false"`
	CSRFDisabled        bool   `envconfig:"CSRF_DISABLED" default:"false"`
	// CSRFCookieDomain scopes the CSRF cookie so the double-submit token is
	// readable across sibling subdomains (e.g. ".id.qeet.in" lets the hosted
	// login app read a token issued by the API). Empty = host-only.
	CSRFCookieDomain string `envconfig:"CSRF_COOKIE_DOMAIN" default:""`

	// AppBaseURL is the frontend origin used to build links in emails
	// (password reset, magic links, invites).
	AppBaseURL string `envconfig:"APP_BASE_URL" default:"http://localhost:3000"`

	// LoginBaseURL is the origin of the hosted login app (qeetid-login) that
	// the OAuth authorize flow redirects to for sign-in and consent.
	LoginBaseURL string `envconfig:"LOGIN_BASE_URL" default:"http://localhost:3004"`

	// GeoCountryHeader is the request header a trusted upstream proxy (e.g.
	// Cloudflare's CF-IPCountry) sets to the client's resolved country, used
	// as the sole geo signal for impossible-travel risk assessment. Empty
	// (the default) disables that signal — there is no server-side GeoIP
	// lookup, by design. Only meaningful when the deployment actually sits
	// behind a proxy that sets it; an unrecognized header name is
	// indistinguishable from "unset" (always empty), which is safe (fail-open).
	GeoCountryHeader string `envconfig:"GEO_COUNTRY_HEADER" default:""`

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

	// RedisURL enables shared (cross-replica) rate limiting, e.g.
	// redis://:pass@host:6379/0. Empty = in-process limits (single instance).
	RedisURL string `envconfig:"REDIS_URL" default:""`

	// NATSURL enables real cross-product event fan-out: the transactional outbox
	// dispatcher publishes drained domain events to NATS (subject = event topic,
	// e.g. nats://host:4222). Empty (default) keeps the dependency-free log-only
	// publisher, so single-product / self-host setups are unaffected.
	NATSURL string `envconfig:"NATS_URL" default:""`

	// Card payments (Stripe / Razorpay) for paid plan changes. Each provider is
	// OFF until its keys are set; with none configured, billing stays on the
	// internal invoice-only model (a paid plan change activates directly).
	// Routing: INR → Razorpay, every other currency → Stripe.
	StripeSecretKey       string `envconfig:"STRIPE_SECRET_KEY" default:""`
	StripeWebhookSecret   string `envconfig:"STRIPE_WEBHOOK_SECRET" default:""`
	RazorpayKeyID         string `envconfig:"RAZORPAY_KEY_ID" default:""`
	RazorpayKeySecret     string `envconfig:"RAZORPAY_KEY_SECRET" default:""`
	RazorpayWebhookSecret string `envconfig:"RAZORPAY_WEBHOOK_SECRET" default:""`

	// BreachedPasswordCheck enables breached-password detection (Have I Been
	// Pwned k-anonymity range API) on every password-setting flow. OFF by
	// default so dev/CI and offline deploys are unaffected, and FAIL-OPEN at
	// runtime so a HIBP outage never blocks signups (see internal/platform/hibp).
	BreachedPasswordCheck bool `envconfig:"BREACHED_PASSWORD_CHECK" default:"false"`
	// BreachedPasswordMinCount is the breach-sighting threshold at or above
	// which a password is rejected (1 = reject anything seen even once).
	BreachedPasswordMinCount int `envconfig:"BREACHED_PASSWORD_MIN_COUNT" default:"1"`
	// BreachedPasswordAPIURL overrides the Pwned Passwords base URL (tests /
	// self-hosted mirrors). Empty uses the public api.pwnedpasswords.com.
	BreachedPasswordAPIURL string `envconfig:"BREACHED_PASSWORD_API_URL" default:""`

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
	switch c.SecretsProvider {
	case "", "static":
		if strings.TrimSpace(c.SecretsKey) == "" {
			problems = append(problems, "SECRETS_KEY is required with SECRETS_PROVIDER=static (base64 AES key; `openssl rand -base64 32`)")
		}
	case "aws-kms":
		if strings.TrimSpace(c.KMSKeyID) == "" {
			problems = append(problems, "KMS_KEY_ID is required with SECRETS_PROVIDER=aws-kms (the KMS key ARN/id)")
		}
		if strings.TrimSpace(c.SecretsWrappedDEK) == "" {
			problems = append(problems, "SECRETS_WRAPPED_DEK is required with SECRETS_PROVIDER=aws-kms (base64 KMS CiphertextBlob of the wrapped data key)")
		}
	default:
		problems = append(problems, fmt.Sprintf("SECRETS_PROVIDER %q is invalid (want \"static\" or \"aws-kms\")", c.SecretsProvider))
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

// TracingConfig builds the tracing setup from the loaded config. An empty
// OTelEndpoint yields a no-op tracer (tracing disabled).
func (c *Config) TracingConfig() tracing.Config {
	return tracing.Config{
		Endpoint:    c.OTelEndpoint,
		ServiceName: c.ServiceName,
		ServiceEnv:  c.ServiceEnv,
		SampleRatio: c.OTelSampleRatio,
	}
}
