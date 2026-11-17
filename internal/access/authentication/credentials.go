package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// forgotten is each kind of credential ForgetCredentials removes, with the
// statement that removes userID's ($1).
var forgotten = []struct{ kind, sql string }{
	{"passkeys", `DELETE FROM auth.passkey_credentials WHERE user_id = $1`},
	{"passkey_ceremonies", `DELETE FROM auth.webauthn_sessions WHERE user_id = $1`},
	{"totp", `DELETE FROM auth.mfa_totp WHERE user_id = $1`},
	{"recovery_codes", `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`},
	{"otp_factors", `DELETE FROM auth.mfa_otp_factors WHERE user_id = $1`},
	{"push_devices", `DELETE FROM auth.mfa_push_devices WHERE user_id = $1`},
	{"push_challenges", `DELETE FROM auth.mfa_push_challenges WHERE user_id = $1 AND status = 'pending'`},
	{"push_pairings", `DELETE FROM auth.mfa_push_pairings WHERE user_id = $1 AND used_at IS NULL`},
	{"step_ups", `DELETE FROM auth.mfa_verifications WHERE user_id = $1`},
	{"pending_verifications", `DELETE FROM account.email_verifications WHERE user_id = $1`},
	{"pending_phone_verifications", `DELETE FROM account.phone_verifications WHERE user_id = $1`},
	{"linked_accounts", `DELETE FROM account.external_identities WHERE user_id = $1`},
	{"console_sign_ins", `DELETE FROM auth.platform_social_identities WHERE user_id = $1`},
	{"console_link_codes", `DELETE FROM auth.platform_social_link_codes WHERE user_id = $1`},
	{"sign_in_codes", `DELETE FROM auth.login_codes WHERE user_id = $1`},
	{"api_keys", `UPDATE auth.api_keys SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`},
}

// ForgetCredentials removes, inside tx, every way userID signs in or acts that
// someone could have set up before the address was proved: its password
// (unless keepPassword), passkeys, second factors, pending verifications,
// linked accounts, unexchanged sign-in codes and personal API keys (revoked).
// Its sessions are EndSignIns' to end. It returns how many of each it removed.
func ForgetCredentials(ctx context.Context, tx pgx.Tx, userID uuid.UUID, keepPassword bool) (map[string]int64, error) {
	steps := forgotten
	if !keepPassword {
		steps = append(steps[:len(steps):len(steps)], struct{ kind, sql string }{"password", `DELETE FROM auth.password_credentials WHERE user_id = $1`})
	}
	removed := map[string]int64{}
	for _, step := range steps {
		tag, err := tx.Exec(ctx, step.sql, userID)
		if err != nil {
			return nil, err
		}
		if n := tag.RowsAffected(); n > 0 {
			removed[step.kind] = n
		}
	}
	return removed, nil
}
