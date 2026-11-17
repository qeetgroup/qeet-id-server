package retention

import (
	"context"
	"errors"
	"fmt"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// Sweep is one platform-wide retention rule: a statement that deletes at most
// $1 rows nothing needs any more from one table.
type Sweep struct {
	Name  string // what it deletes, as logged
	Query string
}

// SignInSweeps delete sign-in state once it is spent: links, codes, states and
// requests a day after they expire (kept that long so a late click is told the
// link expired rather than that it is unknown), and failed sign-in and wrong
// application secret counters a week after the last failure, once no lock or
// throttle is in force. A week is longer than any lockout window.
var SignInSweeps = []Sweep{
	{"authorization codes", `DELETE FROM auth.oidc_authorization_codes WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oidc_authorization_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"consent requests", `DELETE FROM auth.oidc_consent_requests WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oidc_consent_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"device codes", `DELETE FROM auth.oidc_device_codes WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oidc_device_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"backchannel requests", `DELETE FROM auth.oidc_ciba_requests WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oidc_ciba_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"sign-in links", `DELETE FROM auth.magic_links WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.magic_links c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"password resets", `DELETE FROM auth.password_resets WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.password_resets c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"email verifications", `DELETE FROM account.email_verifications WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM account.email_verifications c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"phone verifications", `DELETE FROM account.phone_verifications WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM account.phone_verifications c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"SAML requests", `DELETE FROM auth.saml_authn_requests WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.saml_authn_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"federated sign-in codes", `DELETE FROM auth.login_codes WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.login_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"federated sign-in states", `DELETE FROM auth.oauth_states WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oauth_states c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"platform social link codes", `DELETE FROM auth.platform_social_link_codes WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.platform_social_link_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"connected-account states", `DELETE FROM organization.token_vault_connect_states WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM organization.token_vault_connect_states c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"second-factor sign-ins", `DELETE FROM auth.mfa_login_challenges WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.mfa_login_challenges c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT $1))`},
	{"failed sign-in counts", `DELETE FROM auth.login_attempts WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.login_attempts c
		WHERE c.last_failed_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
		LIMIT $1))`},
	{"failed sign-in counts by network", `DELETE FROM auth.login_attempts_by_network WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.login_attempts_by_network c
		WHERE c.last_failed_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
		LIMIT $1))`},
	{"application secret failures", `DELETE FROM auth.oidc_client_auth_lockouts WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.oidc_client_auth_lockouts c
		WHERE c.last_failure_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
		LIMIT $1))`},
	{"failed sign-ins by source", `DELETE FROM auth.login_source_failures WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.login_source_failures c WHERE c.last_failed_at < NOW() - INTERVAL '7 days' LIMIT $1))`},
	{"source throttles", `DELETE FROM auth.login_source_throttles WHERE ctid = ANY(ARRAY(
		SELECT c.ctid FROM auth.login_source_throttles c WHERE c.throttled_until < NOW() - INTERVAL '7 days' LIMIT $1))`},
}

// RecordSweeps delete records once they stop being useful: finished webhook
// deliveries after 30 days (logout deliveries after a week), bot detections
// after 30 days, directory sync events and notifications after 90, security
// events and audit anomalies 90 days after they are resolved or a year after
// they were raised, invitations 90 days after they lapse, application grants a
// week after they end, and access decisions after 30 days. A delivery still to
// be made, an open alert and a live grant are kept. audit.events goes by each
// organization's plan instead (audit.PurgeExpired).
var RecordSweeps = []Sweep{
	{"webhook deliveries", `DELETE FROM organization.webhook_deliveries WHERE ctid = ANY(ARRAY(
		SELECT d.ctid FROM organization.webhook_deliveries d
		WHERE d.delivered_at < NOW() - INTERVAL '30 days' OR d.dead_at < NOW() - INTERVAL '30 days'
		LIMIT $1))`},
	{"logout deliveries", `DELETE FROM auth.oidc_logout_deliveries WHERE ctid = ANY(ARRAY(
		SELECT d.ctid FROM auth.oidc_logout_deliveries d
		WHERE d.delivered_at < NOW() - INTERVAL '7 days' OR d.failed_at < NOW() - INTERVAL '7 days'
		LIMIT $1))`},
	{"bot detections", `DELETE FROM auth.bot_events WHERE ctid = ANY(ARRAY(
		SELECT e.ctid FROM auth.bot_events e WHERE e.created_at < NOW() - INTERVAL '30 days' LIMIT $1))`},
	{"security events", `DELETE FROM auth.security_events WHERE ctid = ANY(ARRAY(
		SELECT e.ctid FROM auth.security_events e
		WHERE e.resolved_at < NOW() - INTERVAL '90 days' OR e.created_at < NOW() - INTERVAL '365 days'
		LIMIT $1))`},
	{"audit anomalies", `DELETE FROM audit.anomalies WHERE ctid = ANY(ARRAY(
		SELECT a.ctid FROM audit.anomalies a
		WHERE a.resolved_at < NOW() - INTERVAL '90 days' OR a.created_at < NOW() - INTERVAL '365 days'
		LIMIT $1))`},
	{"directory sync events", `DELETE FROM organization.directory_events WHERE ctid = ANY(ARRAY(
		SELECT e.ctid FROM organization.directory_events e WHERE e.started_at < NOW() - INTERVAL '90 days' LIMIT $1))`},
	{"notifications", `DELETE FROM auth.notifications WHERE ctid = ANY(ARRAY(
		SELECT n.ctid FROM auth.notifications n WHERE n.created_at < NOW() - INTERVAL '90 days' LIMIT $1))`},
	{"access decisions", `DELETE FROM auth.authz_decisions WHERE ctid = ANY(ARRAY(
		SELECT d.ctid FROM auth.authz_decisions d WHERE d.decided_at < NOW() - INTERVAL '30 days' LIMIT $1))`},
	// 13 months, so a year-on-year comparison and the last invoice's month remain.
	{"monthly active users", `DELETE FROM organization.monthly_active_users WHERE ctid = ANY(ARRAY(
		SELECT m.ctid FROM organization.monthly_active_users m
		WHERE m.month < (date_trunc('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '13 months')::date LIMIT $1))`},
	{"invitations", `DELETE FROM organization.invites WHERE ctid = ANY(ARRAY(
		SELECT i.ctid FROM organization.invites i WHERE i.expires_at < NOW() - INTERVAL '90 days' LIMIT $1))`},
	// Oldest first, so a token goes no later than the one it was renewed from.
	{"application grants", `DELETE FROM auth.oidc_refresh_tokens WHERE ctid = ANY(ARRAY(
		SELECT t.ctid FROM auth.oidc_refresh_tokens t WHERE t.grant_expires_at < NOW() - INTERVAL '7 days'
		ORDER BY t.issued_at, t.id LIMIT $1))`},
}

// RunSweeps runs each sweep in batches (postgres.PurgeInBatches) and returns
// how many rows each deleted. A failing sweep doesn't stop the rest; their
// errors are returned together.
func RunSweeps(ctx context.Context, db postgres.Execer, sweeps []Sweep) (map[string]int64, error) {
	deleted := make(map[string]int64, len(sweeps))
	var errs []error
	for _, s := range sweeps {
		n, err := postgres.PurgeInBatches(ctx, db, s.Query)
		deleted[s.Name] = n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	return deleted, errors.Join(errs...)
}
