package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
)

// forgetter removes one kind of credential of an account and says how many.
type forgetter = func(context.Context, uuid.UUID) (int64, error)

// forgotten is each kind of credential ForgetCredentials removes, with the
// query that removes an account's, through q.
func forgotten(q *dbgen.Queries) []struct {
	kind   string
	forget forgetter
} {
	return []struct {
		kind   string
		forget forgetter
	}{
		{"passkeys", q.ForgetPasskeys},
		{"passkey_ceremonies", q.ForgetPasskeyCeremonies},
		{"totp", q.ForgetTOTP},
		{"recovery_codes", q.ForgetRecoveryCodes},
		{"otp_factors", q.ForgetOTPFactors},
		{"push_devices", q.ForgetPushDevices},
		{"push_challenges", q.ForgetPushChallenges},
		{"push_pairings", q.ForgetPushPairings},
		{"step_ups", q.ForgetStepUps},
		{"pending_verifications", q.ForgetEmailVerifications},
		{"pending_phone_verifications", q.ForgetPhoneVerifications},
		{"linked_accounts", q.ForgetLinkedAccounts},
		{"console_sign_ins", q.ForgetConsoleSignIns},
		{"console_link_codes", q.ForgetConsoleLinkCodes},
		{"sign_in_codes", q.ForgetSignInCodes},
		{"api_keys", q.ForgetAPIKeys},
	}
}

// ForgetCredentials removes, inside tx, every way userID signs in or acts that
// someone could have set up before the address was proved: its password
// (unless keepPassword), passkeys, second factors, pending verifications,
// linked accounts, unexchanged sign-in codes and personal API keys (revoked).
// Its sessions are EndSignIns' to end. It returns how many of each it removed.
func ForgetCredentials(ctx context.Context, tx pgx.Tx, userID uuid.UUID, keepPassword bool) (map[string]int64, error) {
	q := dbgen.New(tx)
	steps := forgotten(q)
	if !keepPassword {
		steps = append(steps, struct {
			kind   string
			forget forgetter
		}{"password", q.ForgetPassword})
	}
	removed := map[string]int64{}
	for _, step := range steps {
		n, err := step.forget(ctx, userID)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			removed[step.kind] = n
		}
	}
	return removed, nil
}
