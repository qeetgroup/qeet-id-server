//go:build integration

package retention

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// expiries are a row's expiry two days ago, past the grace, and an hour ago,
// within it.
const expiries = `unnest(ARRAY[NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 hour']) AS e`

// sweepCase is one table's rows for a sweep: insert writes rows it should
// delete and rows it should keep, and left counts those still there.
type sweepCase struct {
	sweep  string
	insert string
	args   []any
	left   string // counts the rows by key, $1
	key    any
	keep   int
}

// world is what the sweep cases' rows refer to.
type world struct {
	organization, user, login, connection, oidc, subscription uuid.UUID
	events                                                    [4]uuid.UUID
	client, tag                                               string
}

func newWorld(t *testing.T) world {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	w := world{organization: dbtest.Organization(t), client: dbtest.Unique("app"), tag: dbtest.Unique("sweep")}
	w.user = dbtest.User(t, w.organization, w.organization).ID
	for _, s := range []struct {
		sql  string
		args []any
		into *uuid.UUID
	}{
		{`INSERT INTO auth.login_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour') RETURNING id`, []any{w.tag, w.user}, &w.login},
		{`INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate) VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert') RETURNING id`, []any{w.organization}, &w.connection},
		{`INSERT INTO organization.webhook_subscriptions (organization_id, url, secret_ct, secret_nonce) VALUES ($1, 'https://hooks.example.test', '\x00', '\x00') RETURNING id`, []any{w.organization}, &w.subscription},
		{`INSERT INTO organization.oidc_connections (organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'Entra', 'https://login.example.test', 'qeet', '\x00', '\x00') RETURNING id`, []any{w.organization}, &w.oidc},
	} {
		if err := pool.QueryRow(ctx, s.sql, s.args...).Scan(s.into); err != nil {
			t.Fatalf("%s: %v", s.sql, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for i := range w.events {
		id := uuid.New()
		if err := audit.Record(ctx, tx, audit.Event{OrganizationID: &w.organization, ActorUserID: &w.user, Action: "user.updated",
			ResourceType: "user", ResourceID: &id}); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM audit.events WHERE resource_id = $1`, id).Scan(&w.events[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return w
}

// signInCases are rows of every table SignInSweeps cover.
func signInCases(w world) []sweepCase {
	byTag := func(table, column string) string {
		return `SELECT count(*) FROM ` + table + ` WHERE ` + column + ` LIKE $1::text || '%'`
	}
	return []sweepCase{
		{"authorization codes", `INSERT INTO auth.oidc_authorization_codes (code_hash, client_id, user_id, organization_id, redirect_uri, scopes, expires_at)
			SELECT gen_random_uuid()::text, $1, $2, $3, 'https://app.example.test/cb', '{openid}', e FROM ` + expiries,
			[]any{w.client, w.user, w.organization}, `SELECT count(*) FROM auth.oidc_authorization_codes WHERE organization_id = $1`, w.organization, 1},
		{"consent requests", `INSERT INTO auth.oidc_consent_requests (login_session_id, user_id, client_id, redirect_uri, expires_at)
			SELECT $1, $2, $3, 'https://app.example.test/cb', e FROM ` + expiries,
			[]any{w.login, w.user, w.client}, `SELECT count(*) FROM auth.oidc_consent_requests WHERE user_id = $1`, w.user, 1},
		{"device codes", `INSERT INTO auth.oidc_device_codes (device_code_hash, user_code, client_id, organization_id, expires_at)
			SELECT gen_random_uuid()::text, gen_random_uuid()::text, $1, $2, e FROM ` + expiries,
			[]any{w.client, w.organization}, `SELECT count(*) FROM auth.oidc_device_codes WHERE organization_id = $1`, w.organization, 1},
		{"backchannel requests", `INSERT INTO auth.oidc_ciba_requests (auth_req_id_hash, client_id, organization_id, user_id, expires_at)
			SELECT gen_random_uuid()::text, $1, $2, $3, e FROM ` + expiries,
			[]any{w.client, w.organization, w.user}, `SELECT count(*) FROM auth.oidc_ciba_requests WHERE organization_id = $1`, w.organization, 1},
		{"sign-in links", `INSERT INTO auth.magic_links (organization_id, email, token_hash, expires_at)
			SELECT $1, 'a@example.test', gen_random_uuid()::text, e FROM ` + expiries,
			[]any{w.organization}, `SELECT count(*) FROM auth.magic_links WHERE organization_id = $1`, w.organization, 1},
		{"password resets", `INSERT INTO auth.password_resets (user_id, token_hash, expires_at)
			SELECT $1, gen_random_uuid()::text, e FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM auth.password_resets WHERE user_id = $1`, w.user, 1},
		{"email verifications", `INSERT INTO account.email_verifications (user_id, email, code_hash, expires_at, purpose)
			SELECT $1, 'a@example.test', 'hash', e, 'verify_email' FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM account.email_verifications WHERE user_id = $1`, w.user, 1},
		{"phone verifications", `INSERT INTO account.phone_verifications (user_id, phone, code_hash, expires_at)
			SELECT $1, '+15550100', 'hash', e FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM account.phone_verifications WHERE user_id = $1`, w.user, 1},
		{"SAML requests", `INSERT INTO auth.saml_authn_requests (request_id, connection_id, expires_at)
			SELECT gen_random_uuid()::text, $1, e FROM ` + expiries,
			[]any{w.connection}, `SELECT count(*) FROM auth.saml_authn_requests WHERE connection_id = $1`, w.connection, 1},
		{"federated sign-in codes", `INSERT INTO auth.login_codes (code_hash, kind, user_id, expires_at)
			SELECT gen_random_uuid()::text, 'platform_social', $1, e FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1`, w.user, 1},
		{"federated sign-in states", `INSERT INTO auth.oauth_states (state_hash, kind, provider, code_verifier, redirect_uri, expires_at, link_user_id)
			SELECT gen_random_uuid()::text, 'platform_social', 'google', 'v', 'https://id.example.test/cb', e, $1 FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM auth.oauth_states WHERE link_user_id = $1`, w.user, 1},
		{"platform social link codes", `INSERT INTO auth.platform_social_link_codes (code_hash, user_id, provider, subject, expires_at)
			SELECT gen_random_uuid()::text, $1, 'google', 'g-1', e FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM auth.platform_social_link_codes WHERE user_id = $1`, w.user, 1},
		{"connected-account states", `INSERT INTO organization.token_vault_connect_states (state, organization_id, user_id, provider, expires_at)
			SELECT gen_random_uuid()::text, $1, $2, 'slack', e FROM ` + expiries,
			[]any{w.organization, w.user}, `SELECT count(*) FROM organization.token_vault_connect_states WHERE organization_id = $1`, w.organization, 1},
		{"second-factor sign-ins", `INSERT INTO auth.mfa_login_challenges (user_id, expires_at) SELECT $1, e FROM ` + expiries,
			[]any{w.user}, `SELECT count(*) FROM auth.mfa_login_challenges WHERE user_id = $1`, w.user, 1},
		// A counter is kept while recent or while its lock is in force.
		{"failed sign-in counts", `INSERT INTO auth.login_attempts (email, last_failed_at, locked_until) VALUES
			($1::text || '-old', NOW() - INTERVAL '8 days', NULL),
			($1::text || '-locked', NOW() - INTERVAL '8 days', NOW() + INTERVAL '1 hour'),
			($1::text || '-recent', NOW() - INTERVAL '1 day', NULL)`,
			[]any{w.tag}, byTag("auth.login_attempts", "email"), w.tag, 2},
		{"failed sign-in counts by network", `INSERT INTO auth.login_attempts_by_network (email, network, failed_count, first_failed_at, last_failed_at, locked_until) VALUES
			($1::text || '-old', '203.0.113.0/24', 1, NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days'),
			($1::text || '-locked', '203.0.113.0/24', 5, NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days', NOW() + INTERVAL '1 hour'),
			($1::text || '-recent', '203.0.113.0/24', 1, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day', NULL)`,
			[]any{w.tag}, byTag("auth.login_attempts_by_network", "email"), w.tag, 2},
		{"application secret failures", `WITH app AS (
				INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, 'App') RETURNING id)
			INSERT INTO auth.oidc_client_auth_lockouts (client_row_id, source_network, failures, last_failure_at, locked_until)
			SELECT app.id, v.network, 1, v.failed_at, v.locked_until FROM app, (VALUES
				('203.0.113.1', NOW() - INTERVAL '8 days', NULL::timestamptz),
				('203.0.113.2', NOW() - INTERVAL '8 days', NOW() + INTERVAL '1 hour'),
				('203.0.113.3', NOW() - INTERVAL '1 day', NULL::timestamptz)) AS v (network, failed_at, locked_until)`,
			[]any{w.organization, w.client + "-locked"}, `SELECT count(*) FROM auth.oidc_client_auth_lockouts l
				JOIN auth.oidc_clients c ON c.id = l.client_row_id WHERE c.organization_id = $1`, w.organization, 2},
		{"failed sign-ins by source", `INSERT INTO auth.login_source_failures (network, email, last_failed_at) VALUES
			($1, 'old@example.test', NOW() - INTERVAL '8 days'), ($1, 'recent@example.test', NOW() - INTERVAL '1 day')`,
			[]any{w.tag}, `SELECT count(*) FROM auth.login_source_failures WHERE network = $1`, w.tag, 1},
		{"source throttles", `INSERT INTO auth.login_source_throttles (network, throttled_at, throttled_until, distinct_accounts) VALUES
			($1::text || '-old', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days', 30), ($1::text || '-recent', NOW() - INTERVAL '1 hour', NOW(), 30)`,
			[]any{w.tag}, byTag("auth.login_source_throttles", "network"), w.tag, 1},
	}
}

// recordCases are rows of every table RecordSweeps cover.
func recordCases(w world) []sweepCase {
	return []sweepCase{
		// Kept: a recent delivery, and one never made, however old.
		{"webhook deliveries", `INSERT INTO organization.webhook_deliveries (subscription_id, event_id, event_type, payload, delivered_at, dead_at, created_at) VALUES
			($1, gen_random_uuid(), 'user.created', '{}', NOW() - INTERVAL '31 days', NULL, NOW() - INTERVAL '31 days'),
			($1, gen_random_uuid(), 'user.created', '{}', NULL, NOW() - INTERVAL '31 days', NOW() - INTERVAL '32 days'),
			($1, gen_random_uuid(), 'user.created', '{}', NOW() - INTERVAL '1 day', NULL, NOW() - INTERVAL '1 day'),
			($1, gen_random_uuid(), 'user.created', '{}', NULL, NULL, NOW() - INTERVAL '100 days')`,
			[]any{w.subscription}, `SELECT count(*) FROM organization.webhook_deliveries WHERE subscription_id = $1`, w.subscription, 2},
		{"logout deliveries", `INSERT INTO auth.oidc_logout_deliveries (organization_id, client_id, uri, logout_token, delivered_at, failed_at) VALUES
			($1, $2, 'https://app.example.test/logout', 'jwt', NOW() - INTERVAL '8 days', NULL),
			($1, $2, 'https://app.example.test/logout', 'jwt', NULL, NOW() - INTERVAL '8 days'),
			($1, $2, 'https://app.example.test/logout', 'jwt', NULL, NULL)`,
			[]any{w.organization, w.client}, `SELECT count(*) FROM auth.oidc_logout_deliveries WHERE organization_id = $1`, w.organization, 1},
		{"bot detections", `INSERT INTO auth.bot_events (organization_id, score, verdict, created_at) VALUES
			($1, 0.9, 'blocked', NOW() - INTERVAL '31 days'), ($1, 0.9, 'blocked', NOW() - INTERVAL '1 day')`,
			[]any{w.organization}, `SELECT count(*) FROM auth.bot_events WHERE organization_id = $1`, w.organization, 1},
		// Kept: an open event under a year old, and one resolved recently.
		{"security events", `INSERT INTO auth.security_events (organization_id, type, created_at, resolved_at) VALUES
			($1, 'impossible_travel', NOW() - INTERVAL '100 days', NOW() - INTERVAL '91 days'),
			($1, 'impossible_travel', NOW() - INTERVAL '366 days', NULL),
			($1, 'impossible_travel', NOW() - INTERVAL '200 days', NULL),
			($1, 'impossible_travel', NOW() - INTERVAL '20 days', NOW() - INTERVAL '10 days')`,
			[]any{w.organization}, `SELECT count(*) FROM auth.security_events WHERE organization_id = $1`, w.organization, 2},
		{"audit anomalies", `INSERT INTO audit.anomalies (organization_id, event_id, score, status, created_at, resolved_at) VALUES
			($1, $2, 0.9, 'resolved', NOW() - INTERVAL '100 days', NOW() - INTERVAL '91 days'),
			($1, $3, 0.9, 'open', NOW() - INTERVAL '366 days', NULL),
			($1, $4, 0.9, 'open', NOW() - INTERVAL '200 days', NULL),
			($1, $5, 0.9, 'resolved', NOW() - INTERVAL '20 days', NOW() - INTERVAL '10 days')`,
			[]any{w.organization, w.events[0], w.events[1], w.events[2], w.events[3]}, `SELECT count(*) FROM audit.anomalies WHERE organization_id = $1`, w.organization, 2},
		{"directory sync events", `INSERT INTO organization.directory_events (id, organization_id, connection_id, operation, trigger_type, resource_type, started_at, duration_ms, http_status, status)
			SELECT gen_random_uuid(), $1, 'okta', 'sync', 'push', 'user', s, 10, 200, 'success'
			FROM unnest(ARRAY[NOW() - INTERVAL '91 days', NOW() - INTERVAL '1 day']) AS s`,
			[]any{w.organization}, `SELECT count(*) FROM organization.directory_events WHERE organization_id = $1`, w.organization, 1},
		{"notifications", `INSERT INTO auth.notifications (user_id, organization_id, title, created_at) VALUES
			($1, $2, 'Old', NOW() - INTERVAL '91 days'), ($1, $2, 'New', NOW() - INTERVAL '1 day')`,
			[]any{w.user, w.organization}, `SELECT count(*) FROM auth.notifications WHERE user_id = $1`, w.user, 1},
		{"access decisions", `INSERT INTO auth.authz_decisions (organization_id, source, subject, allowed, decided_at) VALUES
			($1, 'check', 'u1', true, NOW() - INTERVAL '31 days'), ($1, 'check', 'u1', false, NOW() - INTERVAL '1 day')`,
			[]any{w.organization}, `SELECT count(*) FROM auth.authz_decisions WHERE organization_id = $1`, w.organization, 1},
		{"monthly active users", `INSERT INTO organization.monthly_active_users (organization_id, month, user_id) VALUES
			($1, (date_trunc('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '14 months')::date, $2),
			($1, (date_trunc('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '13 months')::date, $2),
			($1, date_trunc('month', NOW() AT TIME ZONE 'UTC')::date, $2)`,
			[]any{w.organization, w.user}, `SELECT count(*) FROM organization.monthly_active_users WHERE organization_id = $1`, w.organization, 2},
		{"invitations", `INSERT INTO organization.invites (organization_id, email, token_hash, status, expires_at) VALUES
			($1, 'old@example.test', gen_random_uuid()::text, 'expired', NOW() - INTERVAL '91 days'),
			($1, 'lapsed@example.test', gen_random_uuid()::text, 'expired', NOW() - INTERVAL '10 days'),
			($1, 'pending@example.test', gen_random_uuid()::text, 'pending', NOW() + INTERVAL '7 days')`,
			[]any{w.organization}, `SELECT count(*) FROM organization.invites WHERE organization_id = $1`, w.organization, 2},
		// An ended grant goes whole, its renewed tokens with it; a live one stays.
		{"application grants", `WITH renewed AS (
				INSERT INTO auth.oidc_refresh_tokens (id, grant_id, token_hash, client_id, user_id, organization_id, issued_at, expires_at, grant_expires_at)
				VALUES ($4, $3, gen_random_uuid()::text, $1, $2, $5, NOW() - INTERVAL '20 days', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days')
				RETURNING id
			)
			INSERT INTO auth.oidc_refresh_tokens (id, grant_id, token_hash, client_id, user_id, organization_id, issued_at, expires_at, grant_expires_at, used_at, replaced_by)
			SELECT $3, $3, gen_random_uuid()::text, $1, $2, $5, NOW() - INTERVAL '30 days', NOW() - INTERVAL '19 days', NOW() - INTERVAL '8 days', NOW() - INTERVAL '20 days', id FROM renewed
			UNION ALL
			SELECT gen_random_uuid(), NULL, gen_random_uuid()::text, $1, $2, $5, NOW(), NOW() + INTERVAL '1 hour', NOW() + INTERVAL '30 days', NULL, NULL`,
			[]any{w.client, w.user, uuid.New(), uuid.New(), w.organization}, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1`, w.user, 1},
	}
}

// runCases inserts each case's rows, runs sweeps, and checks each table
// keeps only what it should. Every sweep must have a case.
func runCases(t *testing.T, sweeps []Sweep, cases []sweepCase) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.sweep] = true
		if _, err := pool.Exec(ctx, c.insert, c.args...); err != nil {
			t.Fatalf("%s: %v", c.sweep, err)
		}
	}
	for _, s := range sweeps {
		if !covered[s.Name] {
			t.Errorf("sweep %q has no test case", s.Name)
		}
	}
	deleted, err := RunSweeps(postgres.AcrossOrganizations(ctx), pool, sweeps)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if deleted[c.sweep] == 0 {
			t.Errorf("%s: deleted nothing", c.sweep)
		}
		if n := dbtest.Count(t, c.left, c.key); n != c.keep {
			t.Errorf("%s: %d rows left, want %d", c.sweep, n, c.keep)
		}
	}
}

// TestSignInSweepsDeleteSpentState checks that every sign-in sweep deletes its
// table's spent rows and keeps those within the grace or still in force.
func TestSignInSweepsDeleteSpentState(t *testing.T) {
	runCases(t, SignInSweeps, signInCases(newWorld(t)))
}

// TestRecordSweepsDeleteOldRecords checks that every record sweep deletes its
// table's rows past retention and keeps recent, pending or open ones.
func TestRecordSweepsDeleteOldRecords(t *testing.T) {
	runCases(t, RecordSweeps, recordCases(newWorld(t)))
}

// TestSweepsDrainABacklog checks that a sweep deletes a backlog larger than a
// batch in one run, and that a failing sweep doesn't stop the others.
func TestSweepsDrainABacklog(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	network := dbtest.Unique("net")
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.login_source_failures (network, email, last_failed_at)
		SELECT $1, 'user' || g || '@example.test', NOW() - INTERVAL '8 days' FROM generate_series(1, $2::int) AS g
	`, network, 2*postgres.PurgeBatch+10); err != nil {
		t.Fatal(err)
	}
	var source Sweep
	for _, s := range SignInSweeps {
		if s.Name == "failed sign-ins by source" {
			source = s
		}
	}
	broken := Sweep{"broken", func(*dbgen.Queries, context.Context, int32) (int64, error) { return 0, errors.New("no such table") }}
	deleted, err := RunSweeps(ctx, pool, []Sweep{broken, source})
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("a failing sweep: %v, want its error", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_source_failures WHERE network = $1`, network); n != 0 || deleted[source.Name] < int64(2*postgres.PurgeBatch+10) {
		t.Errorf("%d rows left after deleting %d, want the backlog gone", n, deleted[source.Name])
	}
}
