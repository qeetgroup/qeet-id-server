package config

import (
	"net/url"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/tracing"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// IsDev reports whether this is a developer workstation (SERVICE_ENV=dev), the
// only environment in which the production gates and Secure cookies are off.
func (c *Config) IsDev() bool { return c.ServiceEnv == EnvDev }

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

// SecretsPreviousKeys returns the SECRETS_PREVIOUS_KEYS entries, trimmed,
// empty ones dropped.
func (c *Config) SecretsPreviousKeys() []string { return strutil.SplitList(c.SecretsPreviousKeysRaw) }

// SecretsPreviousWrappedDEKs returns the SECRETS_PREVIOUS_WRAPPED_DEKS
// entries, trimmed, empty ones dropped.
func (c *Config) SecretsPreviousWrappedDEKs() []string {
	return strutil.SplitList(c.SecretsPreviousWrappedDEKsRaw)
}

// AllowedOrigins returns the ALLOWED_ORIGINS entries, trimmed, or ["*"] when
// the variable is empty.
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
