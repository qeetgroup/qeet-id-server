package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Session lifetime limits, for the platform defaults here and for an
// organization's own policy alike. The idle timeout must outlast an access
// token: a client renews when its access token runs out, and a renewal is what
// keeps a session from going idle.
const (
	SessionMaxAgeMin      = time.Hour
	SessionMaxAgeMax      = 365 * 24 * time.Hour
	SessionIdleTimeoutMin = 15 * time.Minute
)

// RefreshTokenReuseGraceMax bounds the refresh reuse grace: a token used again
// later than this is treated as stolen.
const RefreshTokenReuseGraceMax = time.Minute

// checkSessionLifetime rejects session bounds outside the limits above, an
// idle timeout longer than the maximum age, access tokens that outlive the
// shortest idle timeout an organization may set, and a refresh reuse grace,
// shutdown timeout or shutdown drain delay out of range.
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
	if c.RefreshTokenReuseGrace < 0 || c.RefreshTokenReuseGrace > RefreshTokenReuseGraceMax {
		problems = append(problems, "REFRESH_TOKEN_REUSE_GRACE must lie within 0..1m")
	}
	if c.ShutdownTimeout < 5*time.Second || c.ShutdownTimeout > 2*time.Minute {
		problems = append(problems, "SHUTDOWN_TIMEOUT must lie within 5s..2m")
	}
	if c.ShutdownDrainDelay < 0 || c.ShutdownDrainDelay > 30*time.Second || c.ShutdownDrainDelay > c.ShutdownTimeout/2 {
		problems = append(problems, "SHUTDOWN_DRAIN_DELAY must lie within 0..30s and be at most half of SHUTDOWN_TIMEOUT")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid session and timing configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

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

// Validate refuses, outside SERVICE_ENV=dev, any dev-only convenience or insecure default still in
// place: CSRF off, dev trust headers, the payment sandbox, weak or missing keys, wildcard origins,
// hosts wrong for the environment, or no email provider. In dev it checks only SERVICE_ENV and
// SERVICE_PROFILE.
func (c *Config) Validate() error {
	if err := c.checkEnvironment(); err != nil {
		return err
	}
	if c.IsDev() {
		return nil
	}
	var problems []string
	problems = append(problems, c.devConveniences()...)
	problems = append(problems, c.keyProblems()...)
	problems = append(problems, c.emailProblems()...)
	problems = append(problems, c.hostProblems()...)
	if c.PprofAddr != "" {
		if host, _, err := net.SplitHostPort(c.PprofAddr); err != nil || !isLoopbackName(host) && host != "127.0.0.1" && host != "::1" {
			problems = append(problems, "PPROF_ADDR must be a loopback address (127.0.0.1:6060): profiles expose the process")
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

// devConveniences are the development-only switches still on.
func (c *Config) devConveniences() []string {
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
	return problems
}

// keyProblems are what is wrong with the signing key and its rotation, the
// egress proxy, the secrets provider and the relay keys.
func (c *Config) keyProblems() []string {
	var problems []string
	if strings.TrimSpace(c.JWTSigningKey) == "" {
		problems = append(problems, "JWT_SIGNING_KEY is required (a PEM private key: EC P-256 to sign ES256, or RSA to sign RS256)")
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
	return problems
}

// emailProblems are what is wrong with the email provider. Without one,
// password resets, invitations and verification codes reach nobody.
func (c *Config) emailProblems() []string {
	var problems []string
	switch c.EmailProvider {
	case "", "smtp":
		if strings.TrimSpace(c.SMTPHost) == "" || strings.TrimSpace(c.SMTPFrom) == "" {
			problems = append(problems, "an email provider is required: set SMTP_HOST and SMTP_FROM, or EMAIL_PROVIDER=ses-api with SMTP_FROM and AWS_REGION")
		}
	case "ses-api":
		if strings.TrimSpace(c.SMTPFrom) == "" || strings.TrimSpace(c.AWSRegion) == "" {
			problems = append(problems, "SMTP_FROM and AWS_REGION are required with EMAIL_PROVIDER=ses-api")
		}
	default:
		problems = append(problems, fmt.Sprintf("EMAIL_PROVIDER %q is invalid (want \"smtp\" or \"ses-api\")", c.EmailProvider))
	}
	return problems
}

// hostProblems are what is wrong with the allowed origins and the public and
// browser-facing hosts for the environment.
func (c *Config) hostProblems() []string {
	var problems []string
	if o := strings.TrimSpace(c.AllowedOriginsRaw); o == "" || o == "*" {
		problems = append(problems, "ALLOWED_ORIGINS must list explicit origins (a wildcard is unsafe with credentialed CORS)")
	}
	if c.PublicBaseURL != "" && !isOrigin(c.PublicBaseURL, c.ServiceEnv == EnvProd) {
		problems = append(problems, "PUBLIC_BASE_URL must be an origin such as https://api.example.com (https in prod)")
	}
	switch c.ServiceEnv {
	case EnvProd:
		if u, err := url.Parse(c.AppBaseURL); err != nil || u.Hostname() == "" || isLocalHost(u.Hostname()) || isAnyKitZoneHost(u.Hostname()) {
			problems = append(problems, "APP_BASE_URL must be a real public origin, not localhost or a kit zone")
		}
		if c.PublicBaseURL == "" {
			problems = append(problems, "PUBLIC_BASE_URL is required in prod, so no absolute URL is built from a request's Host")
		}
		if !isIssuerURL(c.JWTIssuer) {
			problems = append(problems, "JWT_ISSUER must be an https URL with no query or fragment, such as https://api.example.com (OpenID Connect discovery requires it; the default qeet-id is for development)")
		}
	case EnvLocal:
		// A local runtime is reachable only on this machine: its browser-facing
		// hosts must be loopback names, or https on its own kit zone, so it can
		// never be deployed publicly.
		for _, v := range []struct{ name, raw string }{
			{"APP_BASE_URL", c.AppBaseURL},
			{"LOGIN_BASE_URL", c.LoginBaseURL},
		} {
			u, err := url.Parse(v.raw)
			switch {
			case err == nil && isLoopbackName(u.Hostname()):
			case err == nil && isKitZoneHost(u.Hostname(), c.ServiceProfile):
				// Passkeys and Secure cookies need https on a public name.
				if u.Scheme != "https" {
					problems = append(problems, v.name+" must use https on the "+c.ServiceProfile+kitZoneSuffix+" kit zone")
				}
			default:
				problems = append(problems, v.name+" must use localhost, a *.localhost host or https on this profile's kit zone (<profile>"+kitZoneSuffix+") with SERVICE_ENV=local")
			}
		}
	}
	return problems
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

// isOrigin reports whether raw is a bare http(s) origin: a scheme and host name
// with no user, path, query or fragment, not even an empty one. With
// httpsOnly, the scheme must be https.
func isOrigin(raw string, httpsOnly bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && !httpsOnly)
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

// isKitZoneHost reports whether h is in the kit zone of this local profile:
// <profile>.id.qeet.in or a subdomain of it. Another profile's zone, and
// id.qeet.in itself (production), are not.
func isKitZoneHost(h, profile string) bool {
	if !serviceProfiles[profile] {
		return false
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	zone := profile + kitZoneSuffix
	return h == zone || strings.HasSuffix(h, "."+zone)
}

// isAnyKitZoneHost reports whether h is in the kit zone of any local profile.
func isAnyKitZoneHost(h string) bool {
	for profile := range serviceProfiles {
		if isKitZoneHost(h, profile) {
			return true
		}
	}
	return false
}

// isIssuerURL reports whether s can be an OpenID Connect issuer: an https URL
// with a host and no query or fragment (OpenID Connect Discovery 1.0, §3). It
// is what relying parties compare the iss claim and the discovery document to.
func isIssuerURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.HasSuffix(s, "#")
}
