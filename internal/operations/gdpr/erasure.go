package gdpr

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// accountData deletes what an erased account leaves outside its user row and
// the audit trail: credentials and second factors, sign-ins, devices, linked
// accounts, application grants, connected accounts' tokens, memberships,
// directory profiles, inbox, behaviour baseline and AI conversations. Its data
// exports lose their payloads, and verifiable credentials issued to it are
// revoked. $1 is the account.
var accountData = []string{
	`DELETE FROM auth.passkey_credentials WHERE user_id = $1`,
	`DELETE FROM auth.passkey_challenges WHERE user_id = $1`,
	`DELETE FROM auth.webauthn_sessions WHERE user_id = $1`,
	`DELETE FROM auth.mfa_otp_factors WHERE user_id = $1`,
	`DELETE FROM auth.mfa_push_pairings WHERE user_id = $1`,
	`DELETE FROM auth.mfa_push_challenges WHERE user_id = $1`,
	`DELETE FROM auth.mfa_push_devices WHERE user_id = $1`,
	`DELETE FROM auth.mfa_verifications WHERE user_id = $1`,
	`DELETE FROM auth.mfa_login_challenges WHERE user_id = $1`,
	`DELETE FROM auth.mfa_attempt_budgets WHERE user_id = $1`,
	`DELETE FROM auth.mfa_failure_streaks WHERE user_id = $1`,
	`DELETE FROM auth.trusted_devices WHERE user_id = $1`,
	`DELETE FROM auth.sessions WHERE user_id = $1`,
	`DELETE FROM auth.login_sessions WHERE user_id = $1`,
	`DELETE FROM auth.login_context_history WHERE user_id = $1`,
	`DELETE FROM auth.oidc_refresh_tokens WHERE user_id = $1`,
	`DELETE FROM auth.oidc_consents WHERE user_id = $1`,
	`DELETE FROM auth.oidc_consent_requests WHERE user_id = $1`,
	`DELETE FROM auth.oidc_authorization_codes WHERE user_id = $1`,
	`DELETE FROM auth.oidc_device_codes WHERE user_id = $1`,
	`DELETE FROM auth.oidc_ciba_requests WHERE user_id = $1`,
	`DELETE FROM auth.social_login_codes WHERE user_id = $1`,
	`DELETE FROM auth.saml_login_codes WHERE user_id = $1`,
	`DELETE FROM auth.oidc_connection_login_codes WHERE user_id = $1`,
	`DELETE FROM auth.platform_social_codes WHERE user_id = $1`,
	`DELETE FROM auth.platform_social_link_codes WHERE user_id = $1`,
	`DELETE FROM auth.platform_social_states WHERE link_user_id = $1`,
	`DELETE FROM auth.platform_social_identities WHERE user_id = $1`,
	`DELETE FROM "user".external_identities WHERE user_id = $1`,
	`DELETE FROM auth.password_credentials WHERE user_id = $1`,
	`DELETE FROM auth.password_resets WHERE user_id = $1`,
	`DELETE FROM auth.mfa_totp WHERE user_id = $1`,
	`DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`,
	`DELETE FROM "user".email_verifications WHERE user_id = $1`,
	`DELETE FROM "user".phone_verifications WHERE user_id = $1`,
	`DELETE FROM auth.api_keys WHERE user_id = $1`,
	`DELETE FROM auth.notifications WHERE user_id = $1`,
	`DELETE FROM tenant.token_vault_grants WHERE user_id = $1`,
	`DELETE FROM tenant.token_vault_connect_states WHERE user_id = $1`,
	`DELETE FROM tenant.directory_profiles WHERE user_id = $1`,
	`DELETE FROM tenant.directory_alerts WHERE user_id = $1`,
	`DELETE FROM tenant.group_members WHERE user_id = $1`,
	`DELETE FROM rbac.user_roles WHERE user_id = $1`,
	`DELETE FROM audit.actor_baselines WHERE actor_user_id = $1`,
	`DELETE FROM qeetai.conversations WHERE user_id = $1`,
	// A credential issued to the person is revoked and its claims cleared; the
	// row stays so a verifier still learns it is revoked.
	`UPDATE auth.credentials
	 SET subject = 'erased', claims = '{}', revoked_at = COALESCE(revoked_at, NOW()), user_id = NULL
	 WHERE user_id = $1`,
	`UPDATE "user".export_requests
	 SET payload = NULL, lease_owner = NULL, lease_until = NULL,
	     status = CASE status WHEN 'pending' THEN 'failed' WHEN 'ready' THEN 'expired' ELSE status END,
	     error = CASE status WHEN 'pending' THEN 'The account was erased.' ELSE error END,
	     completed_at = COALESCE(completed_at, NOW())
	 WHERE user_id = $1 AND (payload IS NOT NULL OR status = 'pending')`,
}

// addressData deletes what is kept by the account's address rather than its
// ID: sign-in links, failed sign-in counters, and invitations that were
// answered or have lapsed. $1 is the address, lowercased.
var addressData = []string{
	`DELETE FROM auth.magic_links WHERE lower(email) = $1`,
	`DELETE FROM auth.login_attempts WHERE email = $1`,
	`DELETE FROM auth.login_attempts_by_network WHERE email = $1`,
	`DELETE FROM auth.login_source_failures WHERE email = $1`,
	`DELETE FROM tenant.invites WHERE lower(email) = $1 AND (status <> 'pending' OR expires_at <= NOW())`,
}

// eraseAccountData deletes, in tx, the data of the account being erased that
// lies outside its user row; email is the account's address before
// redaction. The caller redacts the user row and keeps the audit trail.
func eraseAccountData(ctx context.Context, tx pgx.Tx, userID uuid.UUID, email string) error {
	for _, stmt := range accountData {
		if _, err := tx.Exec(ctx, stmt, userID); err != nil {
			return err
		}
	}
	address := strings.ToLower(strings.TrimSpace(email))
	for _, stmt := range addressData {
		if _, err := tx.Exec(ctx, stmt, address); err != nil {
			return err
		}
	}
	return nil
}
