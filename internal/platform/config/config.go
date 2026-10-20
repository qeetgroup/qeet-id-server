package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
)

// Recognised SERVICE_ENV values. Load rejects anything else, so the production
// gates in Validate are switched on by an explicit value — never by a typo that
// happens not to equal "dev".
const (
	// EnvDev is a developer workstation. Validate's gates are off, missing keys
	// are generated ephemerally, and cookies are not marked Secure.
	EnvDev = "dev"
	// EnvLocal is a Local-tier runtime of the Qeet ID Kit (qeet-id-kit; the DEV,
	// TEST and STAGING environments, selected by SERVICE_PROFILE).
	// Every production gate applies; the only difference from prod is that its
	// browser-facing hosts must be loopback names (localhost / *.localhost), so
	// it cannot be deployed publicly by mistake.
	EnvLocal = "local"
	// EnvProd is production.
	EnvProd = "prod"
)

// serviceProfiles are the SERVICE_PROFILE values accepted with SERVICE_ENV=local:
// the local DEV, TEST (QA testing) and STAGING (UAT testing) environments.
var serviceProfiles = map[string]bool{"dev": true, "test": true, "staging": true} //nolint:gochecknoglobals // fixed allowlist

type Config struct {
	ServiceName string `envconfig:"SERVICE_NAME" default:"qeet-id"`
	// ServiceEnv is one of EnvDev, EnvLocal or EnvProd (L0 QEET_ENV mapping:
	// dev and local are the Local tier, prod is Production). It has no
	// default: dev switches the production gates off, so a deployment that
	// forgot the setting must not start as one.
	ServiceEnv string `envconfig:"SERVICE_ENV"`
	// ServiceProfile names the local environment ("dev", "test" or "staging"). It
	// is only valid with SERVICE_ENV=local, and is reported on /healthz and in logs.
	ServiceProfile string `envconfig:"SERVICE_PROFILE" default:""`
	HTTPPort       string `envconfig:"HTTP_PORT" default:"4001"`
	// TrustedProxyHops is the number of reverse proxies in front of this server
	// that APPEND to X-Forwarded-For (Caddy, nginx, ALB all do). It decides how
	// the client IP is read — see httpx.ClientIP.
	//
	// 0 (default) ignores X-Forwarded-For entirely and uses the transport peer.
	// That is the safe default: the header is attacker-controlled unless a
	// trusted hop rewrote it, and the client IP keys the login rate limiter and
	// every audit record. A deployment behind exactly one proxy must set 1, or
	// every request will be attributed to the proxy's own address.
	TrustedProxyHops int `envconfig:"TRUSTED_PROXY_HOPS" default:"0"`
	// RelayKeysRaw is a comma-separated list of keys that first-party relays
	// (the console's and hosted login's servers) present to have the client
	// address they forward trusted (see httpx.SetRelayKeys). Empty: no relay is
	// trusted, and relayed requests are judged by the relay's own address. More
	// than one lets a key be rotated without downtime.
	RelayKeysRaw string `envconfig:"RELAY_KEYS" default:""`
	LogLevel     string `envconfig:"LOG_LEVEL" default:"info"`
	// LogFormat controls the log output format. "json" forces JSON lines (good
	// for structured log ingestion and dev with jq). "text" forces the colored
	// logfmt dev handler. Empty auto-selects: text when stdout is a TTY in
	// non-prod, json otherwise.
	LogFormat string `envconfig:"LOG_FORMAT" default:""`

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
	// EmbeddedWorkers runs background dispatchers inside the API process. Set
	// false when cmd/worker is deployed separately; database leases remain the
	// correctness backstop during rollout and mixed-version overlap.
	EmbeddedWorkers bool `envconfig:"EMBEDDED_WORKERS" default:"true"`

	JWTSecret   string `envconfig:"JWT_SECRET" required:"true"`
	JWTIssuer   string `envconfig:"JWT_ISSUER" default:"qeet-id"`
	JWTAudience string `envconfig:"JWT_AUDIENCE" default:"qeet-id"`
	// AccessTokenTTL bounds how long a revoked-but-not-yet-expired access token
	// stays usable: access tokens are stateless JWTs verified by signature alone
	// (no per-request DB revocation check), so this TTL is the hard ceiling on
	// that exposure window. Real mitigation is the session.revoked /
	// token.claims_change webhook signals that let a relying party react at once.
	AccessTokenTTL  time.Duration `envconfig:"ACCESS_TOKEN_TTL" default:"10m"`
	RefreshTokenTTL time.Duration `envconfig:"REFRESH_TOKEN_TTL" default:"720h"`
	// SessionMaxAge and SessionIdleTimeout bound the API and console sessions
	// of an organisation whose security policy sets no bounds of its own, and
	// of accounts with no organisation: a session ends SessionMaxAge after
	// sign-in however active it is, and once it goes SessionIdleTimeout without
	// being renewed. SessionMaxAge also bounds an application's grant. The
	// limits an organisation may set are the same (see checkSessionLifetime).
	SessionMaxAge      time.Duration `envconfig:"SESSION_MAX_AGE" default:"720h"`
	SessionIdleTimeout time.Duration `envconfig:"SESSION_IDLE_TIMEOUT" default:"24h"`

	// JWTSigningKey is the PEM-encoded EC P-256 private key (PKCS#8 or SEC1)
	// used to sign access & ID tokens with ES256. Empty is allowed only in
	// dev, where an ephemeral key is generated at startup (tokens won't
	// survive a restart). Required outside dev (enforced in config gates).
	JWTSigningKey string `envconfig:"JWT_SIGNING_KEY" default:""`
	// JWTRetiredKeys holds one or more concatenated PEM public keys (SPKI or
	// certificate) of previously-active signing keys. They stay verifiable
	// during the rotation grace window; new tokens are never signed with them.
	JWTRetiredKeys string `envconfig:"JWT_RETIRED_KEYS" default:""`
	// JWTActivateSigningKey promotes JWT_SIGNING_KEY from candidate to active in
	// the shared registry. Leave false while pre-staging a key on every replica;
	// set true only for the activation rollout.
	JWTActivateSigningKey bool `envconfig:"JWT_ACTIVATE_SIGNING_KEY" default:"false"`
	// JWTSigningKeyRetireGrace keeps the previous public key verifiable after
	// activation. It must exceed the longest access-token lifetime in use.
	JWTSigningKeyRetireGrace     time.Duration `envconfig:"JWT_SIGNING_KEY_RETIRE_GRACE" default:"720h"`
	JWTSigningKeyRefreshInterval time.Duration `envconfig:"JWT_SIGNING_KEY_REFRESH_INTERVAL" default:"5s"`

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

	HTTPReadTimeout       time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout      time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`
	HTTPReadHeaderTimeout time.Duration `envconfig:"HTTP_READ_HEADER_TIMEOUT" default:"5s"`
	HTTPIdleTimeout       time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"60s"`
	HTTPMaxHeaderBytes    int           `envconfig:"HTTP_MAX_HEADER_BYTES" default:"65536"`

	// EgressProxyURL routes tenant-configured outbound HTTP (webhooks, auth
	// hooks, SIEM sinks, social/token-vault calls) through a forward proxy.
	// Ambient HTTPS_PROXY is ignored on purpose — see egress.Options.ProxyURL.
	// When set, the proxy resolves destinations, so it owns address filtering.
	EgressProxyURL string `envconfig:"EGRESS_PROXY_URL" default:""`

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
	LoginBaseURL string `envconfig:"LOGIN_BASE_URL" default:"http://localhost:3003"`

	// SalesEmail receives in-app "Contact sales" lead notifications (Enterprise).
	SalesEmail string `envconfig:"SALES_EMAIL" default:"sales@qeet.in"`

	// Platform-level social login for the console's own Qeet ID accounts
	// (tenant-less — distinct from the per-tenant social providers admins
	// configure for their end users). Each provider is OFF until its client
	// id/secret are set. Google only for now.
	GoogleClientID        string `envconfig:"GOOGLE_CLIENT_ID" default:""`
	GoogleClientSecret    string `envconfig:"GOOGLE_CLIENT_SECRET" default:""`
	MicrosoftClientID     string `envconfig:"MICROSOFT_CLIENT_ID" default:""`
	MicrosoftClientSecret string `envconfig:"MICROSOFT_CLIENT_SECRET" default:""`
	GithubClientID        string `envconfig:"GITHUB_CLIENT_ID" default:""`
	GithubClientSecret    string `envconfig:"GITHUB_CLIENT_SECRET" default:""`
	// Sign in with Apple: client secret is a signed ES256 JWT derived from these,
	// so it needs the Services ID + Team ID + Key ID + .p8 private key (not a
	// static secret). All four required to enable.
	AppleClientID   string `envconfig:"APPLE_CLIENT_ID" default:""`
	AppleTeamID     string `envconfig:"APPLE_TEAM_ID" default:""`
	AppleKeyID      string `envconfig:"APPLE_KEY_ID" default:""`
	ApplePrivateKey string `envconfig:"APPLE_PRIVATE_KEY" default:""`

	// GeoCountryHeader is the request header a trusted upstream proxy (e.g.
	// Cloudflare's CF-IPCountry) sets to the client's resolved country, used
	// as the sole geo signal for impossible-travel risk assessment. Empty
	// (the default) disables that signal — there is no server-side GeoIP
	// lookup, by design. Only meaningful when the deployment actually sits
	// behind a proxy that sets it; an unrecognized header name is
	// indistinguishable from "unset" (always empty), which is safe (fail-open).
	GeoCountryHeader string `envconfig:"GEO_COUNTRY_HEADER" default:""`

	// EmailProvider selects the email transport: "smtp" (default) or "ses-api".
	// Use "ses-api" in regions that offer the SES API but no SMTP endpoint
	// (e.g. ap-south-2). The SES API path uses the AWS credential chain +
	// AWS_REGION and only needs SMTP_FROM (SMTP host/creds are ignored).
	EmailProvider string `envconfig:"EMAIL_PROVIDER" default:"smtp"`
	// AWSRegion is used by the SES-API email provider (and any other AWS SDK
	// client) so endpoint resolution never fails on a missing region.
	AWSRegion string `envconfig:"AWS_REGION" default:""`

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
	StripeSecretKey       string `envconfig:"STRIPE_SECRET_KEY" default:""`
	StripeWebhookSecret   string `envconfig:"STRIPE_WEBHOOK_SECRET" default:""`
	RazorpayKeyID         string `envconfig:"RAZORPAY_KEY_ID" default:""`
	RazorpayKeySecret     string `envconfig:"RAZORPAY_KEY_SECRET" default:""`
	RazorpayWebhookSecret string `envconfig:"RAZORPAY_WEBHOOK_SECRET" default:""`

	// Provider routing by billing country. PaymentDefaultProvider ("stripe" or
	// "razorpay") serves any country without an explicit route in
	// PaymentCountryRoutes, a comma-separated "CC:provider" list (e.g.
	// "IN:razorpay,US:stripe"). When checkout sends no country, routing falls back
	// to currency (INR → Razorpay, else the default).
	PaymentDefaultProvider string `envconfig:"PAYMENT_DEFAULT_PROVIDER" default:"stripe"`
	PaymentCountryRoutes   string `envconfig:"PAYMENT_COUNTRY_ROUTES" default:"IN:razorpay"`

	// BillingAllowUnpaidActivation enables manual/invoice-only billing: a paid
	// plan change with no usable card provider activates directly (recording an
	// invoice) instead of being refused. OFF by default, so a paid plan is never
	// granted without either a completed card payment or this explicit opt-in.
	BillingAllowUnpaidActivation bool `envconfig:"BILLING_ALLOW_UNPAID_ACTIVATION" default:"false"`

	// Invoice tax (GST/VAT). OFF by default so no tax is computed until the
	// operator sets their registered jurisdiction — tax is money-sensitive and
	// must never be charged on a guess. BillingSellerState (India) drives the
	// intra-state CGST+SGST vs inter-state IGST split.
	BillingTaxEnabled    bool   `envconfig:"BILLING_TAX_ENABLED" default:"false"`
	BillingSellerCountry string `envconfig:"BILLING_SELLER_COUNTRY" default:"IN"`
	BillingSellerState   string `envconfig:"BILLING_SELLER_STATE" default:""`
	BillingGSTRateBps    int    `envconfig:"BILLING_GST_RATE_BPS" default:"1800"`

	// PaymentSandbox enables a dev-only fake provider that serves a local mock
	// hosted-checkout page and completes payment on click — the full
	// redirect→success flow with no real Stripe/Razorpay account. When on it
	// serves every checkout regardless of country/currency. Refused outside dev.
	PaymentSandbox bool `envconfig:"PAYMENT_SANDBOX" default:"false"`
	// PaymentSandboxBaseURL is this backend's own public origin, used to build the
	// sandbox mock-checkout URL the browser is redirected to.
	PaymentSandboxBaseURL string `envconfig:"PAYMENT_SANDBOX_BASE_URL" default:"http://localhost:4001"`

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

	// Sign-in lockout (internal/access/authentication/lockout.go). After
	// LOGIN_LOCKOUT_THRESHOLD failed password sign-ins to one account from one
	// network, each within LOGIN_LOCKOUT_WINDOW of the last, the account is
	// locked for that network for LOGIN_LOCKOUT_DURATION. These are the
	// platform defaults; a tenant may set its own within the _MIN/_MAX bounds
	// through its authentication policy. Windows and durations are whole
	// minutes; Load refuses a default outside its bounds.
	LoginLockoutThreshold    int           `envconfig:"LOGIN_LOCKOUT_THRESHOLD" default:"5"`
	LoginLockoutWindow       time.Duration `envconfig:"LOGIN_LOCKOUT_WINDOW" default:"15m"`
	LoginLockoutDuration     time.Duration `envconfig:"LOGIN_LOCKOUT_DURATION" default:"15m"`
	LoginLockoutThresholdMin int           `envconfig:"LOGIN_LOCKOUT_THRESHOLD_MIN" default:"3"`
	LoginLockoutThresholdMax int           `envconfig:"LOGIN_LOCKOUT_THRESHOLD_MAX" default:"20"`
	LoginLockoutWindowMin    time.Duration `envconfig:"LOGIN_LOCKOUT_WINDOW_MIN" default:"1m"`
	LoginLockoutWindowMax    time.Duration `envconfig:"LOGIN_LOCKOUT_WINDOW_MAX" default:"24h"`
	LoginLockoutDurationMin  time.Duration `envconfig:"LOGIN_LOCKOUT_DURATION_MIN" default:"1m"`
	LoginLockoutDurationMax  time.Duration `envconfig:"LOGIN_LOCKOUT_DURATION_MAX" default:"24h"`
	// LoginLockoutAccountMultiplier sets the looser per-account cap: threshold
	// × multiplier failures from any mix of networks lock the account
	// everywhere, so an attack spread over many networks stays bounded.
	// At least 2, or one network could lock the owner out again.
	LoginLockoutAccountMultiplier int `envconfig:"LOGIN_LOCKOUT_ACCOUNT_MULTIPLIER" default:"4"`
	// A source network that fails password sign-in against LOGIN_SPRAY_ACCOUNTS
	// distinct accounts within LOGIN_SPRAY_WINDOW is refused password sign-in
	// for LOGIN_SPRAY_BLOCK (broad-and-shallow spraying). Raise the count for a
	// deployment whose users share one address (a large NAT).
	LoginSprayAccounts int           `envconfig:"LOGIN_SPRAY_ACCOUNTS" default:"30"`
	LoginSprayWindow   time.Duration `envconfig:"LOGIN_SPRAY_WINDOW" default:"15m"`
	LoginSprayBlock    time.Duration `envconfig:"LOGIN_SPRAY_BLOCK" default:"15m"`

	// WebAuthn Relying Party config. Empty values default from AppBaseURL /
	// ServiceName (see WebAuthnRP). RP_ID is the effective domain (no scheme/
	// port); RP_ORIGINS is a comma-separated allow-list of full origins.
	WebAuthnRPID          string `envconfig:"WEBAUTHN_RP_ID" default:""`
	WebAuthnRPDisplayName string `envconfig:"WEBAUTHN_RP_DISPLAY_NAME" default:""`
	WebAuthnRPOriginsRaw  string `envconfig:"WEBAUTHN_RP_ORIGINS" default:""`

	// ExpoPushURL is the Expo push notification API endpoint. Defaults to the
	// public Expo push service. Override for self-hosted / proxied deployments.
	ExpoPushURL string `envconfig:"EXPO_PUSH_URL" default:"https://exp.host/--/api/v2/push/send"`
	// ExpoAccessToken is sent with every push when set; Expo requires it once
	// enhanced push security is turned on for the mobile app's project.
	ExpoAccessToken string `envconfig:"EXPO_ACCESS_TOKEN" default:""`

	// AI Qeetai (enterprise feature). Empty QeetaiProvider disables the
	// feature: /status returns configured=false, conversation CRUD still works,
	// and .../messages returns 409 qeetai_unconfigured.
	//
	// QeetaiProvider selects the backend: "anthropic" (default when set) or
	// "openai" (also any OpenAI-compatible endpoint: Groq, OpenRouter, Gemini …
	// via QeetaiBaseURL). QeetaiAPIKey is held server-side only — never
	// serialized to any response.
	QeetaiProvider  string `envconfig:"QEETAI_PROVIDER" default:""`
	QeetaiAPIKey    string `envconfig:"QEETAI_API_KEY" default:""`
	QeetaiModel     string `envconfig:"QEETAI_MODEL" default:"claude-sonnet-5"`
	QeetaiMaxTokens int    `envconfig:"QEETAI_MAX_TOKENS" default:"4096"`
	QeetaiBaseURL   string `envconfig:"QEETAI_BASE_URL" default:""`
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return nil, err
	}
	if err := c.checkEnvironment(); err != nil {
		return nil, err
	}
	if err := c.checkSignInLockout(); err != nil {
		return nil, err
	}
	if err := c.checkSessionLifetime(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Session lifetime limits, for the platform defaults here and for an
// organisation's own policy alike. The idle timeout must outlast an access
// token: a client renews when its access token runs out, and a renewal is what
// keeps a session from going idle.
const (
	SessionMaxAgeMin      = time.Hour
	SessionMaxAgeMax      = 365 * 24 * time.Hour
	SessionIdleTimeoutMin = 15 * time.Minute
)

// checkSessionLifetime rejects session bounds outside the limits above, an
// idle timeout longer than the maximum age, and access tokens that outlive the
// shortest idle timeout an organisation may set.
func (c *Config) checkSessionLifetime() error {
	var problems []string
	if c.SessionMaxAge < SessionMaxAgeMin || c.SessionMaxAge > SessionMaxAgeMax {
		problems = append(problems, "SESSION_MAX_AGE must lie within 1h..8760h")
	}
	if c.SessionIdleTimeout < SessionIdleTimeoutMin || c.SessionIdleTimeout > c.SessionMaxAge {
		problems = append(problems, "SESSION_IDLE_TIMEOUT must be at least 15m and at most SESSION_MAX_AGE")
	}
	if c.AccessTokenTTL <= 0 || c.AccessTokenTTL >= SessionIdleTimeoutMin {
		problems = append(problems, "ACCESS_TOKEN_TTL must be positive and shorter than 15m, the shortest session idle timeout")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid session lifetime configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// checkSignInLockout rejects lockout settings that would not protect sign-in:
// a bound that is not positive or not whole minutes, a minimum above its
// maximum, a default outside its bounds, an account multiplier below 2, or a
// spraying limit that is not positive.
func (c *Config) checkSignInLockout() error {
	var problems []string
	minutes := func(name string, d time.Duration) {
		if d < time.Minute || d%time.Minute != 0 {
			problems = append(problems, name+" must be a whole number of minutes, at least 1m")
		}
	}
	minutes("LOGIN_LOCKOUT_WINDOW", c.LoginLockoutWindow)
	minutes("LOGIN_LOCKOUT_DURATION", c.LoginLockoutDuration)
	minutes("LOGIN_LOCKOUT_WINDOW_MIN", c.LoginLockoutWindowMin)
	minutes("LOGIN_LOCKOUT_WINDOW_MAX", c.LoginLockoutWindowMax)
	minutes("LOGIN_LOCKOUT_DURATION_MIN", c.LoginLockoutDurationMin)
	minutes("LOGIN_LOCKOUT_DURATION_MAX", c.LoginLockoutDurationMax)
	if c.LoginLockoutThresholdMin < 1 {
		problems = append(problems, "LOGIN_LOCKOUT_THRESHOLD_MIN must be at least 1")
	}
	if c.LoginLockoutThreshold < c.LoginLockoutThresholdMin || c.LoginLockoutThreshold > c.LoginLockoutThresholdMax {
		problems = append(problems, "LOGIN_LOCKOUT_THRESHOLD must lie within LOGIN_LOCKOUT_THRESHOLD_MIN..LOGIN_LOCKOUT_THRESHOLD_MAX")
	}
	if c.LoginLockoutWindow < c.LoginLockoutWindowMin || c.LoginLockoutWindow > c.LoginLockoutWindowMax {
		problems = append(problems, "LOGIN_LOCKOUT_WINDOW must lie within LOGIN_LOCKOUT_WINDOW_MIN..LOGIN_LOCKOUT_WINDOW_MAX")
	}
	if c.LoginLockoutDuration < c.LoginLockoutDurationMin || c.LoginLockoutDuration > c.LoginLockoutDurationMax {
		problems = append(problems, "LOGIN_LOCKOUT_DURATION must lie within LOGIN_LOCKOUT_DURATION_MIN..LOGIN_LOCKOUT_DURATION_MAX")
	}
	if c.LoginLockoutAccountMultiplier < 2 {
		problems = append(problems, "LOGIN_LOCKOUT_ACCOUNT_MULTIPLIER must be at least 2")
	}
	if c.LoginSprayAccounts < 2 || c.LoginSprayWindow <= 0 || c.LoginSprayBlock <= 0 {
		problems = append(problems, "LOGIN_SPRAY_ACCOUNTS must be at least 2, and LOGIN_SPRAY_WINDOW and LOGIN_SPRAY_BLOCK positive")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid sign-in lockout configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// IsDev reports whether this is a developer workstation (SERVICE_ENV=dev), the
// only environment in which the production gates and Secure cookies are off.
func (c *Config) IsDev() bool { return c.ServiceEnv == EnvDev }

// checkEnvironment rejects a missing or unrecognised SERVICE_ENV, and a
// SERVICE_PROFILE that is unknown or used outside SERVICE_ENV=local.
func (c *Config) checkEnvironment() error {
	switch c.ServiceEnv {
	case EnvDev, EnvLocal, EnvProd:
	case "":
		return fmt.Errorf("SERVICE_ENV is not set: set it to %q (a developer workstation), %q (the Qeet ID Kit) or %q", EnvDev, EnvLocal, EnvProd)
	default:
		return fmt.Errorf("SERVICE_ENV %q is not recognised (want %q, %q or %q)", c.ServiceEnv, EnvDev, EnvLocal, EnvProd)
	}
	if c.ServiceProfile == "" {
		return nil
	}
	if c.ServiceEnv != EnvLocal {
		return fmt.Errorf("SERVICE_PROFILE is only valid with SERVICE_ENV=%q (got SERVICE_ENV=%q)", EnvLocal, c.ServiceEnv)
	}
	if !serviceProfiles[c.ServiceProfile] {
		return fmt.Errorf("SERVICE_PROFILE %q is not recognised (want \"dev\", \"test\" or \"staging\")", c.ServiceProfile)
	}
	return nil
}

// Validate enforces production-safety invariants. Inside SERVICE_ENV=dev it is
// a no-op (dev needs the escape hatches and self-signed defaults); in local and
// prod it refuses to start when a dev-only convenience or an insecure default
// is still in place. Failing loudly here is far cheaper than discovering a
// production deploy shipped with CSRF off or a placeholder secret.
func (c *Config) Validate() error {
	if err := c.checkEnvironment(); err != nil {
		return err
	}
	if c.IsDev() {
		return nil
	}
	var problems []string
	if c.CSRFDisabled {
		problems = append(problems, "CSRF_DISABLED must not be set outside dev")
	}
	if c.AuthDevTrustHeaders {
		problems = append(problems, "AUTH_DEV_TRUST_HEADERS must not be set outside dev")
	}
	if c.PaymentSandbox {
		problems = append(problems, "PAYMENT_SANDBOX must not be set outside dev (it takes payments without charging)")
	}
	if isWeakSecret(c.JWTSecret) {
		problems = append(problems, "JWT_SECRET is missing, shorter than 32 chars, or a known placeholder")
	}
	if strings.TrimSpace(c.JWTSigningKey) == "" {
		problems = append(problems, "JWT_SIGNING_KEY is required (PEM EC P-256 private key for ES256 token signing)")
	}
	if c.JWTSigningKeyRetireGrace < c.AccessTokenTTL || c.JWTSigningKeyRetireGrace < time.Hour {
		problems = append(problems, "JWT_SIGNING_KEY_RETIRE_GRACE must cover ACCESS_TOKEN_TTL and be at least 1h")
	}
	if c.JWTSigningKeyRefreshInterval <= 0 {
		problems = append(problems, "JWT_SIGNING_KEY_REFRESH_INTERVAL must be positive")
	}
	if raw := strings.TrimSpace(c.EgressProxyURL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" {
			problems = append(problems, "EGRESS_PROXY_URL must be an absolute URL with a host")
		}
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
	for _, k := range c.RelayKeys() {
		if isWeakSecret(k) {
			problems = append(problems, "RELAY_KEYS: every key must be at least 32 characters and not a placeholder (`openssl rand -base64 32`)")
			break
		}
	}
	if o := strings.TrimSpace(c.AllowedOriginsRaw); o == "" || o == "*" {
		problems = append(problems, "ALLOWED_ORIGINS must list explicit origins (a wildcard is unsafe with credentialed CORS)")
	}
	switch c.ServiceEnv {
	case EnvProd:
		if u, err := url.Parse(c.AppBaseURL); err != nil || u.Hostname() == "" || isLocalHost(u.Hostname()) {
			problems = append(problems, "APP_BASE_URL must be a real public origin, not localhost")
		}
	case EnvLocal:
		// A local runtime is reachable only on this machine: its browser-facing
		// hosts must be loopback names, so it can never be deployed publicly.
		for _, v := range []struct{ name, raw string }{
			{"APP_BASE_URL", c.AppBaseURL},
			{"LOGIN_BASE_URL", c.LoginBaseURL},
		} {
			if u, err := url.Parse(v.raw); err != nil || !isLoopbackName(u.Hostname()) {
				problems = append(problems, v.name+" must use localhost or a *.localhost host with SERVICE_ENV=local")
			}
		}
	}
	// Qeetai: if a provider is named, the API key must also be set.
	if strings.TrimSpace(c.QeetaiProvider) != "" && strings.TrimSpace(c.QeetaiAPIKey) == "" {
		problems = append(problems, "QEETAI_API_KEY is required when QEETAI_PROVIDER is set")
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
	return isLoopbackName(h) || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".local")
}

// isLoopbackName reports whether h is "localhost" or a subdomain of it
// (RFC 6761: *.localhost always resolves to loopback).
func isLoopbackName(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// RelayKeys returns the configured relay keys (RELAY_KEYS), trimmed, empty
// ones dropped.
func (c *Config) RelayKeys() []string {
	var out []string
	for _, k := range strings.Split(c.RelayKeysRaw, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
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
// AppBaseURL and LoginBaseURL when the explicit env vars are unset. The hosted
// login runs passkey sign-in, sign-up and enrolment from its own origin.
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
		login := strings.TrimSuffix(c.LoginBaseURL, "/")
		if login != "" && login != strings.TrimSuffix(c.AppBaseURL, "/") {
			origins = append(origins, login)
		}
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
