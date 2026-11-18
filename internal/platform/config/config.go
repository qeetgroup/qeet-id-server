// Package config loads the server's settings from environment variables and
// checks them for the deployment environment (SERVICE_ENV).
package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Recognised SERVICE_ENV values. Load rejects anything else, so Validate's
// production gates switch on by an explicit value, never by a typo. Local keeps
// every gate, but its browser-facing hosts must be loopback names or https on
// its own kit zone (see kitZoneSuffix), so it can't be deployed publicly.
const (
	EnvDev   = "dev"   // a developer workstation: gates off, missing keys generated, cookies not Secure
	EnvLocal = "local" // a Qeet ID Kit runtime (SERVICE_PROFILE dev, test or staging)
	EnvProd  = "prod"  // production
)

// serviceProfiles are the SERVICE_PROFILE values accepted with SERVICE_ENV=local:
// the local DEV, TEST (QA testing) and STAGING (UAT testing) environments.
var serviceProfiles = map[string]bool{"dev": true, "test": true, "staging": true} //nolint:gochecknoglobals // fixed allowlist

// kitZoneSuffix completes a local profile's public kit zone, <profile>.id.qeet.in.
// Public DNS points those names at 127.0.0.1, so they reach only the machine
// running the kit, yet unlike *.localhost they can register real https callbacks
// (Google, Microsoft, Apple sign-in).
const kitZoneSuffix = ".id.qeet.in"

// Config is the server configuration, read from the environment by Load.
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
	// TrustedProxyHops is how many reverse proxies in front of this server append
	// to X-Forwarded-For (see httpx.ClientIP). The default 0 ignores the header,
	// which callers control; behind one proxy set 1, or every request is
	// attributed to the proxy's own address.
	TrustedProxyHops int `envconfig:"TRUSTED_PROXY_HOPS" default:"0"`
	// RelayKeysRaw is a comma-separated list of keys that first-party relays (the
	// console's and hosted login's servers) present to have the client address
	// they forward trusted (see httpx.SetRelayKeys); several allow rotation.
	// Empty: no relay is trusted.
	RelayKeysRaw string `envconfig:"RELAY_KEYS" default:""`
	// MetricsToken is the bearer token a scraper presents for /metrics. Empty:
	// /metrics is open in development and off everywhere else, as its counters
	// (sign-in throttles among them) tell an attacker how close they are to a
	// limit.
	MetricsToken string `envconfig:"METRICS_TOKEN" default:""`
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

	JWTIssuer   string `envconfig:"JWT_ISSUER" default:"qeet-id"`
	JWTAudience string `envconfig:"JWT_AUDIENCE" default:"qeet-id"`
	// AccessTokenTTL caps how long a revoked access token stays usable to a
	// verifier that checks it offline. Introspection (POST /oauth/introspect) and
	// the session.revoked and token.claims_change signals report revocation at once.
	AccessTokenTTL  time.Duration `envconfig:"ACCESS_TOKEN_TTL" default:"10m"`
	RefreshTokenTTL time.Duration `envconfig:"REFRESH_TOKEN_TTL" default:"720h"`
	// RefreshTokenReuseGrace is how long after a refresh token's rotation the
	// same token gets the rotation's pair again, for a client that raced itself
	// or lost the answer, rather than ending the session as theft. 0 turns it
	// off; at most RefreshTokenReuseGraceMax.
	RefreshTokenReuseGrace time.Duration `envconfig:"REFRESH_TOKEN_REUSE_GRACE" default:"30s"`
	// SessionMaxAge and SessionIdleTimeout bound API and console sessions when the
	// organization's policy sets none (or there is no organization): a session ends
	// SessionMaxAge after sign-in, or after SessionIdleTimeout without renewal.
	// SessionMaxAge also bounds an application's grant. See checkSessionLifetime.
	SessionMaxAge      time.Duration `envconfig:"SESSION_MAX_AGE" default:"720h"`
	SessionIdleTimeout time.Duration `envconfig:"SESSION_IDLE_TIMEOUT" default:"24h"`

	// JWTSigningKey is the PEM private key that signs access & ID tokens: an EC
	// P-256 key signs ES256, an RSA key of 2048 bits or more RS256. Empty is
	// allowed only in dev, which uses the database's key or makes its first.
	// Required outside dev (enforced in config gates).
	JWTSigningKey string `envconfig:"JWT_SIGNING_KEY" default:""`
	// JWTRetiredKeys holds concatenated PEM public keys (SPKI or certificate) of
	// retired signing keys: they verify tokens during the rotation grace window but
	// never sign new ones.
	JWTRetiredKeys string `envconfig:"JWT_RETIRED_KEYS" default:""`
	// JWTActivateSigningKey promotes JWT_SIGNING_KEY from candidate to active in
	// the shared registry. Leave false while pre-staging a key on every replica;
	// set true only for the activation rollout.
	JWTActivateSigningKey bool `envconfig:"JWT_ACTIVATE_SIGNING_KEY" default:"false"`
	// JWTSigningKeyRetireGrace keeps the previous public key verifiable after
	// activation. It must exceed the longest access-token lifetime in use.
	JWTSigningKeyRetireGrace     time.Duration `envconfig:"JWT_SIGNING_KEY_RETIRE_GRACE" default:"720h"`
	JWTSigningKeyRefreshInterval time.Duration `envconfig:"JWT_SIGNING_KEY_REFRESH_INTERVAL" default:"5s"`

	// SAMLIdPKey and SAMLIdPCert are the PEM RSA key and X.509 certificate that
	// sign SAML assertions when Qeet ID is the IdP. Both are required outside dev;
	// in dev, leaving either empty generates an ephemeral self-signed pair, and SPs
	// must re-import the metadata after each restart.
	SAMLIdPKey  string `envconfig:"SAML_IDP_KEY" default:""`
	SAMLIdPCert string `envconfig:"SAML_IDP_CERT" default:""`

	// SecretsKey is the base64-encoded AES key (16/24/32 bytes) that encrypts
	// every stored secret. Required outside dev
	// when SECRETS_PROVIDER=static; in dev an ephemeral key is generated if
	// unset. Generate with `openssl rand -base64 32`.
	//
	// Every stored value names the key that sealed it, so the key can be
	// rotated without making anything unreadable:
	//  1. With several instances, first add the new key to SECRETS_PREVIOUS_KEYS
	//     on all of them, so each can read what the others will seal with it.
	//  2. Make the new key SECRETS_KEY and move the old one to
	//     SECRETS_PREVIOUS_KEYS. New values are sealed with the new key, and the
	//     secrets-reencrypt job re-seals the stored ones in the background.
	//  3. When envelope_rows_on_old_keys is 0 for every column and the
	//     audit-chain-verify job has run since (it signs the audit checkpoints
	//     again with the new key), remove the old key from SECRETS_PREVIOUS_KEYS.
	//
	// With aws-kms the steps are the same with SECRETS_WRAPPED_DEK and
	// SECRETS_PREVIOUS_WRAPPED_DEKS; a key moved from static to aws-kms stays
	// readable in SECRETS_PREVIOUS_KEYS.
	SecretsKey string `envconfig:"SECRETS_KEY" default:""`
	// SecretsPreviousKeysRaw lists earlier data keys, base64 and comma-separated:
	// they decrypt what they sealed but never encrypt (see SecretsKey).
	SecretsPreviousKeysRaw string `envconfig:"SECRETS_PREVIOUS_KEYS" default:""`

	// SecretsProvider selects how the vault data-encryption key is sourced:
	//   static  — from SECRETS_KEY (default)
	//   aws-kms — unwrapped at boot from KMS_KEY_ID + SECRETS_WRAPPED_DEK
	SecretsProvider string `envconfig:"SECRETS_PROVIDER" default:"static"`
	// KMSKeyID is the AWS KMS key ARN/id used to unwrap the DEK (aws-kms only).
	KMSKeyID string `envconfig:"KMS_KEY_ID" default:""`
	// SecretsWrappedDEK is the base64 KMS CiphertextBlob of the wrapped data key
	// (output of `aws kms generate-data-key`), unwrapped at boot (aws-kms only).
	SecretsWrappedDEK string `envconfig:"SECRETS_WRAPPED_DEK" default:""`
	// SecretsPreviousWrappedDEKsRaw lists earlier SECRETS_WRAPPED_DEK values,
	// comma-separated, unwrapped with KMS_KEY_ID to decrypt only (aws-kms only).
	SecretsPreviousWrappedDEKsRaw string `envconfig:"SECRETS_PREVIOUS_WRAPPED_DEKS" default:""`

	HTTPReadTimeout       time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout      time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`
	HTTPReadHeaderTimeout time.Duration `envconfig:"HTTP_READ_HEADER_TIMEOUT" default:"5s"`
	HTTPIdleTimeout       time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"60s"`
	HTTPMaxHeaderBytes    int           `envconfig:"HTTP_MAX_HEADER_BYTES" default:"65536"`
	// ShutdownTimeout bounds a stop, from the signal to exit; its phases share
	// it. Give the container longer to stop (30s at the default). 5s..2m.
	ShutdownTimeout time.Duration `envconfig:"SHUTDOWN_TIMEOUT" default:"20s"`
	// ShutdownDrainDelay is how long a stopping server answers /readyz 503
	// before it stops taking requests, so a load balancer sends no new ones
	// first. 0..30s and at most half of ShutdownTimeout; 0 suits a server with
	// no load balancer in front.
	ShutdownDrainDelay time.Duration `envconfig:"SHUTDOWN_DRAIN_DELAY" default:"5s"`

	// EgressProxyURL routes organization-configured outbound HTTP (webhooks, auth
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

	// PublicBaseURL is this API's own public origin (e.g. https://api.id.qeet.in).
	// Every absolute URL the API returns is built on it: SAML entity IDs, OIDC
	// discovery, SCIM locations and OAuth callbacks. Required in prod; empty
	// elsewhere derives the origin from the request.
	PublicBaseURL string `envconfig:"PUBLIC_BASE_URL" default:""`

	// SalesEmail receives in-app "Contact sales" lead notifications (Enterprise).
	SalesEmail string `envconfig:"SALES_EMAIL" default:"sales@qeet.in"`

	// Platform social login (Google, Microsoft, GitHub, Apple) for the console's
	// own Qeet ID accounts, distinct from the per-organization providers admins set up
	// for their users. Each provider is off until its credentials are set.
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

	// GeoCountryHeader names the header a trusted upstream proxy sets to the
	// client's country (e.g. CF-IPCountry); see httpx.SetGeoCountryHeader. It is the
	// only geo signal, for risk checks and sessions; there is no server-side GeoIP.
	// Empty, or a header the proxy doesn't set, means no country.
	GeoCountryHeader string `envconfig:"GEO_COUNTRY_HEADER" default:""`
	// GeoCityHeader names the header the same proxy sets to the client's city
	// (e.g. CloudFront-Viewer-City), recorded on audit events and sessions.
	GeoCityHeader string `envconfig:"GEO_CITY_HEADER" default:""`

	// EmailProvider selects the email transport: "smtp" (default) or "ses-api".
	// Use "ses-api" in regions that offer the SES API but no SMTP endpoint
	// (e.g. ap-south-2). The SES API path uses the AWS credential chain +
	// AWS_REGION and only needs SMTP_FROM (SMTP host/creds are ignored).
	// Outside dev one of the two must be configured (see Validate).
	EmailProvider string `envconfig:"EMAIL_PROVIDER" default:"smtp"`
	// AWSRegion is used by the SES-API email provider (and any other AWS SDK
	// client) so endpoint resolution never fails on a missing region.
	AWSRegion string `envconfig:"AWS_REGION" default:""`
	// HostingRegion is the region this deployment runs in, which every
	// organization is created in and shows as its region; empty means
	// AWS_REGION, else us-east-1. One deployment holds its data in one region,
	// so an organization can't choose another.
	HostingRegion string `envconfig:"HOSTING_REGION" default:""`

	// Email (SMTP) — provider-agnostic (Amazon SES, SendGrid, Mailgun, Postmark).
	// In dev, an empty SMTPHost logs emails instead of sending them.
	SMTPHost     string `envconfig:"SMTP_HOST" default:""`
	SMTPPort     string `envconfig:"SMTP_PORT" default:"587"`
	SMTPUsername string `envconfig:"SMTP_USERNAME" default:""`
	SMTPPassword string `envconfig:"SMTP_PASSWORD" default:""`
	SMTPFrom     string `envconfig:"SMTP_FROM" default:""`
	// SESConfigurationSet names the SES configuration set every email is sent
	// with (ses-api), whose event destination publishes deliveries, bounces
	// and complaints to SNS and on to POST /v1/webhooks/ses.
	SESConfigurationSet string `envconfig:"SES_CONFIGURATION_SET" default:""`
	// SESEventsTopicARNs are the SNS topics POST /v1/webhooks/ses accepts
	// (comma-separated). Anyone can create an SNS topic, so a message from any
	// other is refused; with none set the endpoint is off.
	SESEventsTopicARNs []string `envconfig:"SES_EVENTS_TOPIC_ARN" default:""`

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
	// "razorpay") serves countries without a route in PaymentCountryRoutes, a
	// comma-separated "CC:provider" list such as "IN:razorpay,US:stripe". Checkout
	// without a country routes by currency: INR to Razorpay, anything else to Stripe.
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
	// BillingSupplierGSTIN and BillingSAC are printed on every invoice: the
	// seller's GSTIN and the services accounting code of what it sells.
	BillingSupplierGSTIN string `envconfig:"BILLING_SUPPLIER_GSTIN" default:""`
	BillingSAC           string `envconfig:"BILLING_SAC" default:""`
	// BillingPaymentGrace is how long an open invoice may go unpaid: a renewal
	// still unpaid that long after its period ends ends the subscription.
	BillingPaymentGrace time.Duration `envconfig:"BILLING_PAYMENT_GRACE" default:"168h"`

	// PaymentSandbox enables a dev-only fake provider that serves a local mock
	// hosted-checkout page and completes payment on click — the full
	// redirect→success flow with no real Stripe/Razorpay account. When on it
	// serves every checkout regardless of country/currency. Refused outside dev.
	PaymentSandbox bool `envconfig:"PAYMENT_SANDBOX" default:"false"`
	// PaymentSandboxBaseURL is this backend's own public origin, used to build the
	// sandbox mock-checkout URL the browser is redirected to.
	PaymentSandboxBaseURL string `envconfig:"PAYMENT_SANDBOX_BASE_URL" default:"http://localhost:4001"`

	// BreachedPasswordCheck checks every new password against known breaches (the
	// Have I Been Pwned k-anonymity range API). It is on by default; the
	// development .env template turns it off. It fails open, so a HIBP outage
	// never blocks sign-up (see internal/platform/crypto/hibp).
	BreachedPasswordCheck bool `envconfig:"BREACHED_PASSWORD_CHECK" default:"true"`
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

	// Native push for the Qeet ID apps. Each service is off until its credentials are set.
	// APNsAuthKey is the token-signing key (.p8, PEM text) from the Apple Developer account.
	APNsAuthKey  string `envconfig:"APNS_AUTH_KEY" default:""`
	APNsKeyID    string `envconfig:"APNS_KEY_ID" default:""`
	APNsTeamID   string `envconfig:"APNS_TEAM_ID" default:""`
	APNsBundleID string `envconfig:"APNS_BUNDLE_ID" default:"com.qeetgroup.qeetid"`
	// APNsSandbox sends to the development APNs host, for builds signed for development.
	APNsSandbox bool `envconfig:"APNS_SANDBOX" default:"false"`
	// FCMServiceAccount is the Firebase project's service-account key (JSON text) for the
	// Android app.
	FCMServiceAccount string `envconfig:"FCM_SERVICE_ACCOUNT" default:""`

	// Qeet AI platform provider, used by organizations without their own key; with
	// QeetaiProvider empty there is none and such organizations get 409
	// qeetai_unconfigured. QeetaiProvider is "anthropic", "openai" (or any compatible
	// API via QeetaiBaseURL) or "azure"; QeetaiAPIKey never leaves the server.
	QeetaiProvider  string `envconfig:"QEETAI_PROVIDER" default:""`
	QeetaiAPIKey    string `envconfig:"QEETAI_API_KEY" default:""`
	QeetaiModel     string `envconfig:"QEETAI_MODEL" default:"claude-sonnet-5"`
	QeetaiMaxTokens int    `envconfig:"QEETAI_MAX_TOKENS" default:"4096"`
	QeetaiBaseURL   string `envconfig:"QEETAI_BASE_URL" default:""`
}

// Load reads the Config from the environment and rejects an unknown SERVICE_ENV
// or SERVICE_PROFILE and unsafe session lifetime limits. Validate applies the
// production gates.
func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return nil, err
	}
	if err := c.checkEnvironment(); err != nil {
		return nil, err
	}
	if err := c.checkSessionLifetime(); err != nil {
		return nil, err
	}
	return &c, nil
}
