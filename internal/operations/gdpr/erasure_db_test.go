//go:build integration

package gdpr

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// leaveTraces gives the account a row in every table erasure clears, and in
// those kept by its address, as a person who used every feature would.
func leaveTraces(t *testing.T, organization uuid.UUID, a dbtest.Account) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	u, email := a.ID, strings.ToLower(a.Email)
	client, session, login, group, oidc, sp := dbtest.Unique("app"), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	soon := time.Now().Add(time.Hour)
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, 'Payroll')`, []any{organization, client}},
		{`INSERT INTO auth.sessions (id, user_id, organization_id, ip, user_agent) VALUES ($1, $2, $3, '203.0.113.7', 'Firefox')`, []any{session, u, organization}},
		{`INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, name) VALUES ($1, convert_to($2, 'UTF8'), '\x00', 'Phone')`, []any{u, u.String()}},
		{`INSERT INTO auth.webauthn_sessions (user_id, kind, data, expires_at) VALUES ($1, 'registration', '{}', $2)`, []any{u, soon}},
		{`INSERT INTO auth.mfa_otp_factors (user_id, channel, destination) VALUES ($1, 'sms', '+15550100')`, []any{u}},
		{`INSERT INTO auth.mfa_push_devices (user_id, platform, push_token_ct, push_token_nonce, push_token_hash, device_token_hash) VALUES ($1, 'ios', '\x00', '\x00', 'push', 'device')`, []any{u}},
		{`INSERT INTO auth.mfa_push_pairings (user_id, code_hash, expires_at) VALUES ($1, $2, $3)`, []any{u, dbtest.Unique("pair"), soon}},
		{`INSERT INTO auth.mfa_push_challenges (user_id, action) VALUES ($1, 'sign_in')`, []any{u}},
		{`INSERT INTO auth.mfa_verifications (user_id, method, session_id) VALUES ($1, 'totp', $2)`, []any{u, session}},
		{`INSERT INTO auth.mfa_login_challenges (user_id, expires_at) VALUES ($1, $2)`, []any{u, soon}},
		{`INSERT INTO auth.mfa_attempt_budgets (user_id, purpose) VALUES ($1, 'login')`, []any{u}},
		{`INSERT INTO auth.mfa_failure_streaks (user_id) VALUES ($1)`, []any{u}},
		{`INSERT INTO auth.trusted_devices (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, []any{u, dbtest.Unique("device"), soon}},
		{`INSERT INTO auth.login_sessions (id, token_hash, user_id, expires_at) VALUES ($1, $2, $3, $4)`, []any{login, dbtest.Unique("login"), u, soon}},
		{`INSERT INTO auth.login_context_history (organization_id, user_id, device_key, country) VALUES ($1, $2, 'firefox', 'IN')`, []any{organization, u}},
		{`INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at) VALUES ($1, $2, $3, $4, $5)`, []any{dbtest.Unique("rt"), client, u, organization, soon}},
		{`INSERT INTO auth.oidc_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`, []any{u, client}},
		{`INSERT INTO auth.oidc_consent_requests (login_session_id, user_id, client_id, redirect_uri, expires_at) VALUES ($1, $2, $3, 'https://app.example.test/cb', $4)`, []any{login, u, client, soon}},
		{`INSERT INTO auth.oidc_authorization_codes (code_hash, client_id, user_id, organization_id, redirect_uri, scopes, expires_at) VALUES ($1, $2, $3, $4, 'https://app.example.test/cb', '{openid}', $5)`, []any{dbtest.Unique("code"), client, u, organization, soon}},
		{`INSERT INTO auth.oidc_device_codes (device_code_hash, user_code, client_id, organization_id, user_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, []any{dbtest.Unique("dc"), dbtest.Unique("uc"), client, organization, u, soon}},
		{`INSERT INTO auth.oidc_ciba_requests (auth_req_id_hash, client_id, organization_id, user_id, expires_at) VALUES ($1, $2, $3, $4, $5)`, []any{dbtest.Unique("ciba"), client, organization, u, soon}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, provider, expires_at) VALUES ($1, 'social', $2, $3, 'google', $4)`, []any{dbtest.Unique("social"), u, organization, soon}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, connection_id, expires_at) VALUES ($1, 'saml', $2, $3, gen_random_uuid(), $4)`, []any{dbtest.Unique("saml"), u, organization, soon}},
		{`INSERT INTO organization.oidc_connections (id, organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, $2, 'Entra', 'https://login.example.test', 'qeet', '\x00', '\x00')`, []any{oidc, organization}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, connection_id, expires_at) VALUES ($1, 'oidc_connection', $2, $3, $4, $5)`, []any{dbtest.Unique("oidc"), u, organization, oidc, soon}},
		{`INSERT INTO auth.credentials (organization_id, subject, type, claims, user_id) VALUES ($1, $2, 'EmploymentCredential', '{"name": "Asha"}', $3)`, []any{organization, email, u}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, expires_at) VALUES ($1, 'platform_social', $2, $3)`, []any{dbtest.Unique("psc"), u, soon}},
		{`INSERT INTO auth.platform_social_link_codes (code_hash, user_id, provider, subject, email, expires_at) VALUES ($1, $2, 'google', 'g-1', $3, $4)`, []any{dbtest.Unique("link"), u, email, soon}},
		{`INSERT INTO auth.oauth_states (state_hash, kind, provider, code_verifier, redirect_uri, expires_at, link_user_id) VALUES ($1, 'platform_social', 'google', 'v', 'https://id.example.test/cb', $2, $3)`, []any{dbtest.Unique("state"), soon, u}},
		{`INSERT INTO auth.platform_social_identities (user_id, provider, subject, email) VALUES ($1, 'google', $2, $3)`, []any{u, dbtest.Unique("g"), email}},
		{`INSERT INTO account.external_identities (user_id, organization_id, provider, subject, email) VALUES ($1, $2, 'github', $3, $4)`, []any{u, organization, dbtest.Unique("gh"), email}},
		{`INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, []any{u, dbtest.Unique("reset"), soon}},
		{`INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce) VALUES ($1, '\x00', '\x00')`, []any{u}},
		{`INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, 'hash')`, []any{u}},
		{`INSERT INTO account.email_verifications (user_id, email, code_hash, expires_at, purpose) VALUES ($1, $2, 'hash', $3, 'verify_email')`, []any{u, email, soon}},
		{`INSERT INTO account.phone_verifications (user_id, phone, code_hash, expires_at) VALUES ($1, '+15550100', 'hash', $2)`, []any{u, soon}},
		{`INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash) VALUES ($1, $2, 'laptop', $3, 'hash')`, []any{organization, u, dbtest.Unique("qk")}},
		{`INSERT INTO auth.notifications (user_id, organization_id, title) VALUES ($1, $2, 'Welcome')`, []any{u, organization}},
		{`INSERT INTO organization.token_vault_grants (organization_id, user_id, provider, access_token_ct, access_token_nonce) VALUES ($1, $2, 'slack', '\x00', '\x00')`, []any{organization, u}},
		{`INSERT INTO organization.token_vault_connect_states (state, organization_id, user_id, provider, expires_at) VALUES ($1, $2, $3, 'slack', $4)`, []any{dbtest.Unique("vault"), organization, u, soon}},
		{`INSERT INTO organization.directory_profiles (organization_id, user_id, connection_id, profile) VALUES ($1, $2, 'okta', '{"title": "Engineer"}')`, []any{organization, u}},
		{`INSERT INTO organization.directory_alerts (id, organization_id, user_id, name) VALUES ($1, $2, $3, 'Sync failures')`, []any{uuid.New(), organization, u}},
		{`INSERT INTO organization.groups (id, organization_id, name) VALUES ($1, $2, $3)`, []any{group, organization, dbtest.Unique("group")}},
		{`INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, []any{group, u, organization}},
		{`INSERT INTO organization.saml_service_providers (id, organization_id, name, entity_id, acs_url) VALUES ($1, $2, 'Payroll', $3, 'https://sp.example.test/acs')`, []any{sp, organization, dbtest.Unique("https://sp.example.test/")}},
		{`INSERT INTO organization.saml_sp_user_assignments (organization_id, sp_id, user_id) VALUES ($1, $2, $3)`, []any{organization, sp, u}},
		{`INSERT INTO organization.saml_idp_persistent_ids (organization_id, sp_id, user_id, name_id) VALUES ($1, $2, $3, $4)`, []any{organization, sp, u, dbtest.Unique("pid")}},
		{`INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, []any{organization, u}},
		{`INSERT INTO audit.actor_baselines (organization_id, actor_user_id) VALUES ($1, $2)`, []any{organization, u}},
		{`INSERT INTO qeetai.conversations (organization_id, user_id) VALUES ($1, $2)`, []any{organization, u}},
		{`INSERT INTO account.export_requests (organization_id, user_id, subject_id, status, payload, completed_at) VALUES ($1, $2, $2, 'ready', '{"profile": {}}', NOW())`, []any{organization, u}},
		{`INSERT INTO auth.magic_links (email, token_hash, expires_at) VALUES ($1, $2, $3)`, []any{email, dbtest.Unique("magic"), soon}},
		{`INSERT INTO auth.login_attempts (email) VALUES ($1)`, []any{email}},
		{`INSERT INTO auth.login_attempts_by_network (email, network, failed_count, first_failed_at, last_failed_at) VALUES ($1, '203.0.113.0/24', 1, NOW(), NOW())`, []any{email}},
		{`INSERT INTO auth.login_source_failures (network, email, last_failed_at) VALUES ('203.0.113.0/24', $1, NOW())`, []any{email}},
		{`INSERT INTO organization.invites (organization_id, email, token_hash, expires_at, status) VALUES ($1, $2, $3, $4, 'accepted')`, []any{organization, email, dbtest.Unique("invite"), soon}},
		{`UPDATE account.users SET avatar_url = 'https://cdn.example.test/a.png', external_id = 'okta-1', metadata = '{"team": "core"}' WHERE id = $1`, []any{u}},
	} {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("%s: %v", s.sql, err)
		}
	}
}

// due ends an erasure request's grace period by the database's clock, which
// may run behind the test's.
func due(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.purge_requests SET grace_until = NOW() - INTERVAL '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

// erasedRow matches one statement of accountData: the table it changes and
// the column naming the account.
var erasedRow = regexp.MustCompile(`(?s)(?:FROM|UPDATE)\s+(\S+).*WHERE\s+(\w+)\s*=\s*\$1`)

// tracesLeft returns, for each table erasure clears, how many of the
// account's rows are left (an export with its payload counts as one).
func tracesLeft(t *testing.T, userID uuid.UUID, email string) map[string]int {
	t.Helper()
	left := map[string]int{}
	for _, stmt := range accountData {
		m := erasedRow.FindStringSubmatch(stmt)
		if m == nil {
			t.Fatalf("can't read the table of %s", stmt)
		}
		query := `SELECT count(*) FROM ` + m[1] + ` WHERE ` + m[2] + ` = $1`
		if strings.Contains(m[1], "export_requests") {
			query += ` AND payload IS NOT NULL`
		}
		if n := dbtest.Count(t, query, userID); n > 0 {
			left[m[1]] = n
		}
	}
	for _, table := range []string{"auth.magic_links", "auth.login_attempts", "auth.login_attempts_by_network", "auth.login_source_failures", "organization.invites"} {
		if n := dbtest.Count(t, `SELECT count(*) FROM `+table+` WHERE lower(email) = $1`, strings.ToLower(email)); n > 0 {
			left[table] = n
		}
	}
	return left
}

// TestErasureRemovesEveryTrace checks that the sweep's erasure leaves nothing
// of the person but their redacted user row, the erasure request and the
// audit trail, and that another member's data is untouched.
func TestErasureRemovesEveryTrace(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	erased, bystander := account(t, organization), account(t, organization)
	leaveTraces(t, organization, erased)
	leaveTraces(t, organization, bystander)
	if left := tracesLeft(t, erased.ID, erased.Email); len(left) != len(accountData)+len(addressData) {
		t.Fatalf("the traces cover %d tables, want every one erasure clears (%d)", len(left), len(accountData)+len(addressData))
	}

	svc := NewService(dbtest.Pool(t), time.Nanosecond)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/purge", map[string]any{"user_id": erased.ID})
	var req Request
	dbtest.Decode(t, rec, &req)
	due(t, req.ID)
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if status := requestStatus(t, req.ID); status != "completed" {
		t.Fatalf("erasure request %s, want completed", status)
	}
	if left := tracesLeft(t, erased.ID, erased.Email); len(left) > 0 {
		t.Errorf("erasure left %v", left)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email LIKE 'redacted-%' AND avatar_url IS NULL AND external_id IS NULL AND metadata = '{}'`, erased.ID); n != 1 {
		t.Error("the user row wasn't redacted")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.credentials WHERE organization_id = $1 AND subject = 'erased' AND claims = '{}' AND revoked_at IS NOT NULL`, organization); n != 1 {
		t.Errorf("%d credentials revoked and cleared, want the erased person's one", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE resource_id = $1`, req.ID); n != 2 {
		t.Errorf("%d audit events about the request, want them kept (2)", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.export_requests WHERE user_id = $1 AND status = 'expired'`, erased.ID); n != 1 {
		t.Error("the erased person's export wasn't marked expired")
	}
	if left := tracesLeft(t, bystander.ID, bystander.Email); len(left) != len(accountData)+len(addressData) {
		t.Errorf("another member kept data in %d tables, want all %d", len(left), len(accountData)+len(addressData))
	}
}

// TestDeleteOwnAccountRemovesEveryTrace checks that self-service deletion
// erases as much as an organization's erasure does.
func TestDeleteOwnAccountRemovesEveryTrace(t *testing.T) {
	organization := dbtest.Organization(t)
	a := account(t, organization)
	leaveTraces(t, organization, a)
	h := dbtest.Serve(dbtest.Principal(a.ID, organization), (&Handler{Service: NewService(dbtest.Pool(t), 0)}).Mount)
	if rec := dbtest.Do(t, h, http.MethodPost, "/account/delete", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete own account: %d %s", rec.Code, rec.Body.String())
	}
	if left := tracesLeft(t, a.ID, a.Email); len(left) > 0 {
		t.Errorf("deleting the account left %v", left)
	}
}

// TestErasureCoversEveryAccountTable checks that every table whose rows go
// when an account is deleted for good is also cleared by erasure, so a table
// added later can't keep an erased person's data.
func TestErasureCoversEveryAccountTable(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT replace(c.conrelid::regclass::text, '"', ''), a.attname
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		WHERE c.contype = 'f' AND c.confrelid = 'account.users'::regclass AND c.confdeltype = 'c'
		  AND cardinality(c.conkey) = 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	covered := map[string]bool{}
	for _, stmt := range accountData {
		if m := erasedRow.FindStringSubmatch(stmt); m != nil {
			covered[strings.ReplaceAll(m[1], `"`, "")+"."+m[2]] = true
		}
	}
	n := 0
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		n++
		if !covered[table+"."+column] {
			t.Errorf("%s.%s goes with a deleted account but erasure leaves it; add it to accountData", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Fatalf("found %d tables that go with an account; the catalog query is broken", n)
	}
}

// TestErasureOfAnAccountAlreadyGone checks that a request whose account was
// deleted for good in its grace period completes, and keeps naming the
// account.
func TestErasureOfAnAccountAlreadyGone(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	gone := account(t, organization)
	svc := NewService(pool, time.Nanosecond)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	var req Request
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/purge", map[string]any{"user_id": gone.ID}), &req)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET deleted_at = NOW(), status = 'deleted' WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM account.users WHERE id = $1`, gone.ID); err != nil {
		t.Fatalf("delete an account awaiting erasure: %v", err)
	}
	due(t, req.ID)
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []Request `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+organization.String()+"/gdpr/purge", nil), &list)
	if len(list.Items) != 1 || list.Items[0].Status != "completed" || list.Items[0].UserID != gone.ID {
		t.Errorf("requests %+v; want the one, completed, naming the deleted account", list.Items)
	}
	recorded(t, organization, req.ID, "gdpr.erasure_completed", nil, gone.ID)
}
