package mfa

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// consumeTOTPStep marks a TOTP time step used, returning false if that step or
// a later one already was. A code is accepted for about 90s, so this stops one
// code authenticating twice (RFC 6238 §5.2); a single conditional UPDATE lets
// only one of two concurrent submissions win.
func consumeTOTPStep(ctx context.Context, tx pgx.Tx, userID uuid.UUID, step int64) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE auth.mfa_totp
		SET last_used_step = $2
		WHERE user_id = $1
		  AND (last_used_step IS NULL OR last_used_step < $2)
	`, userID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Enrollment is a started authenticator-app setup. Replacing reports that the
// account's confirmed app keeps working until a code from this one confirms it.
type Enrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
	Replacing       bool   `json:"replacing"`
}

// pendingTOTPTTL is how long a new authenticator app set up beside a
// confirmed one may wait for its confirming code before the setup is ignored.
const pendingTOTPTTL = 30 * time.Minute

// StartEnroll starts setting up an authenticator app. While the account holds
// a confirmed app, the new one waits beside it (pending_secret_*) until a code
// from it confirms it, so starting a setup never switches the working app off;
// a pending setup left unconfirmed for pendingTOTPTTL is ignored.
func (s *Service) StartEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (*Enrollment, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-totp", userID.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	var replacing bool
	err = tx.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL FROM auth.mfa_totp WHERE user_id = $1 FOR UPDATE`, userID).
		Scan(&replacing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if replacing {
		_, err = tx.Exec(ctx, `
			UPDATE auth.mfa_totp
			SET pending_secret_ct = $2, pending_secret_nonce = $3, pending_started_at = NOW()
			WHERE user_id = $1
		`, userID, ciphertext, nonce)
	} else {
		_, err = tx.Exec(ctx, `
			INSERT INTO auth.mfa_totp
			    (user_id, secret, secret_ct, secret_nonce, encryption_version)
			VALUES ($1, '', $2, $3, 1)
			ON CONFLICT (user_id) DO UPDATE SET
			    secret = '', secret_ct = EXCLUDED.secret_ct,
			    secret_nonce = EXCLUDED.secret_nonce, encryption_version = 1,
			    confirmed_at = NULL, pending_secret_ct = NULL, pending_secret_nonce = NULL,
			    pending_started_at = NULL
		`, userID, ciphertext, nonce)
	}
	if err != nil {
		return nil, err
	}
	if err := clearMFAAttempt(ctx, tx, userID, PurposeTOTPEnroll); err != nil {
		return nil, err
	}
	return &Enrollment{
		Secret:          secret,
		ProvisioningURL: totp.ProvisioningURL(secret, s.issuer, account),
		Replacing:       replacing,
	}, nil
}

// ConfirmEnroll completes an authenticator-app enrolment with a code from the
// app and returns the new recovery codes.
func (s *Service) ConfirmEnroll(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) ([]string, error) {
	codes, ok, err := s.confirmTOTP(ctx, tx, attempt.userID, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, attemptError(errs.ErrMFATOTPCodeInvalid, attempt.remaining)
	}
	return codes, nil
}

// confirmTOTP confirms the authenticator app being set up with a code from
// it and mints fresh recovery codes. (nil, false, nil) is a wrong code. A
// replacement replaces the confirmed app only here, once its code is right.
func (s *Service) confirmTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, bool, error) {
	qtx := s.q.WithTx(tx)
	var pendingCT, pendingNonce []byte
	var pendingStarted pgtype.Timestamptz
	var confirmed bool
	err := tx.QueryRow(ctx, `
		SELECT pending_secret_ct, pending_secret_nonce, pending_started_at, confirmed_at IS NOT NULL
		FROM auth.mfa_totp WHERE user_id = $1 FOR UPDATE
	`, userID).Scan(&pendingCT, &pendingNonce, &pendingStarted, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errs.ErrMFAEnrollNotStarted
	}
	if err != nil {
		return nil, false, err
	}
	if pendingCT != nil {
		return s.confirmReplacementTOTP(ctx, tx, userID, code, pendingCT, pendingNonce, pendingStarted.Time)
	}
	if confirmed {
		// Nothing is being set up: the confirmed app needs no confirming.
		return nil, false, errs.ErrMFAEnrollNotStarted
	}
	secret, _, err := s.loadTOTP(ctx, tx, userID)
	if err != nil {
		return nil, false, err
	}
	step, ok := totp.VerifyStep(secret, code)
	if !ok {
		return nil, false, nil
	}
	// Burn the step here too, so the code that completed enrollment cannot be
	// immediately replayed against the login/step-up path below.
	fresh, err := consumeTOTPStep(ctx, tx, userID, step)
	if err != nil {
		return nil, false, err
	}
	if !fresh {
		return nil, false, nil
	}
	if err := qtx.ConfirmMFATOTP(ctx, userID); err != nil {
		return nil, false, err
	}
	if err := clearMFAAttempt(ctx, tx, userID, PurposeTOTPEnroll); err != nil {
		return nil, false, err
	}
	// Wipe old recovery codes, mint a fresh batch.
	codes, err := s.mintRecoveryCodes(ctx, tx, userID)
	return codes, err == nil, err
}

// confirmReplacementTOTP confirms a new authenticator app set up beside the
// confirmed one: a right code from it, within pendingTOTPTTL, makes it the
// account's app (the code's step burned against it) and mints fresh recovery
// codes. A setup past its time is refused and leaves the account as it was.
func (s *Service) confirmReplacementTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string, ct, nonce []byte, started time.Time) ([]string, bool, error) {
	if time.Since(started) > pendingTOTPTTL {
		return nil, false, errs.ErrMFAEnrollNotStarted.WithDetail("This authenticator setup has expired. Start it again.")
	}
	if s.box == nil {
		return nil, false, errors.New("MFA secret encryption is unavailable")
	}
	plain, err := s.box.Open(userID, "mfa-totp", userID.String(), ct, nonce)
	if err != nil {
		return nil, false, err
	}
	step, ok := totp.VerifyStep(string(plain), code)
	if !ok {
		return nil, false, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_totp
		SET secret = '', secret_ct = pending_secret_ct, secret_nonce = pending_secret_nonce,
		    encryption_version = 1, confirmed_at = NOW(), last_used_step = $2,
		    pending_secret_ct = NULL, pending_secret_nonce = NULL, pending_started_at = NULL
		WHERE user_id = $1
	`, userID, step); err != nil {
		return nil, false, err
	}
	if err := clearMFAAttempt(ctx, tx, userID, PurposeTOTPEnroll); err != nil {
		return nil, false, err
	}
	codes, err := s.mintRecoveryCodes(ctx, tx, userID)
	return codes, err == nil, err
}

func (s *Service) loadTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, pgtype.Timestamptz, error) {
	var confirmedAt pgtype.Timestamptz
	var legacySecret string
	var ciphertext, nonce []byte
	err := tx.QueryRow(ctx, `
		SELECT secret, secret_ct, secret_nonce, confirmed_at
		FROM auth.mfa_totp
		WHERE user_id = $1
	`, userID).Scan(&legacySecret, &ciphertext, &nonce, &confirmedAt)
	if err != nil {
		return "", confirmedAt, err
	}
	if len(ciphertext) > 0 {
		if s.box == nil {
			return "", confirmedAt, errors.New("MFA secret encryption is unavailable")
		}
		plain, openErr := s.box.Open(userID, "mfa-totp", userID.String(), ciphertext, nonce)
		if openErr != nil {
			return "", confirmedAt, openErr
		}
		return string(plain), confirmedAt, nil
	}
	if legacySecret != "" && s.box != nil {
		ct, newNonce, sealErr := s.box.Seal(userID, "mfa-totp", userID.String(), []byte(legacySecret))
		if sealErr != nil {
			return "", confirmedAt, sealErr
		}
		if _, updateErr := tx.Exec(ctx, `
			UPDATE auth.mfa_totp
			SET secret = '', secret_ct = $2, secret_nonce = $3, encryption_version = 1
			WHERE user_id = $1 AND secret_ct IS NULL
		`, userID, ct, newNonce); updateErr != nil {
			return "", confirmedAt, updateErr
		}
	}
	return legacySecret, confirmedAt, nil
}

const recoveryCodeCount = 10

// mintRecoveryCodes replaces a user's recovery codes with a fresh batch and
// returns the plaintext, the only time it is available; only hashes are stored.
func (s *Service) mintRecoveryCodes(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return nil, err
	}
	out := make([]string, recoveryCodeCount)
	for i := range out {
		c, err := codes.Numeric(10)
		if err != nil {
			return nil, err
		}
		hash, err := password.Hash(c)
		if err != nil {
			return nil, err
		}
		if err := qtx.InsertMFARecoveryCode(ctx, dbgen.InsertMFARecoveryCodeParams{
			UserID:   userID,
			CodeHash: hash,
		}); err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// TOTPStatus reports whether the account has a confirmed authenticator app. A
// replacement being set up beside it doesn't count until it is confirmed.
type TOTPStatus struct {
	Enrolled bool `json:"enrolled"`
}

// TOTPStatus reports whether the user has an authenticator app enrolled.
func (s *Service) TOTPStatus(ctx context.Context, userID uuid.UUID) (*TOTPStatus, error) {
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return &TOTPStatus{Enrolled: err == nil && ts.Valid}, nil
}

// RecoveryStatus summarises a user's backup codes for the account UI.
type RecoveryStatus struct {
	Enrolled  bool `json:"enrolled"`  // TOTP confirmed — recovery codes back a real factor
	Total     int  `json:"total"`     // recovery codes issued
	Remaining int  `json:"remaining"` // recovery codes not yet used
}

// RecoveryStatus reports how many of the user's recovery codes are left.
func (s *Service) RecoveryStatus(ctx context.Context, userID uuid.UUID) (*RecoveryStatus, error) {
	var st RecoveryStatus
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	st.Enrolled = err == nil && ts.Valid
	stats, err := s.q.GetMFARecoveryCodeStats(ctx, userID)
	if err != nil {
		return nil, err
	}
	st.Total = int(stats.Total)
	st.Remaining = int(stats.Remaining)
	return &st, nil
}

// Regenerate issues a fresh set of recovery codes, invalidating the old set.
// Requires confirmed TOTP — recovery codes are a backup for an enrolled factor.
func (s *Service) Regenerate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	ts, err := s.q.WithTx(tx).GetMFATOTPConfirmed(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrMFANotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if !ts.Valid {
		return nil, errs.ErrMFANotConfirmed
	}
	return s.mintRecoveryCodes(ctx, tx, userID)
}

// Disable removes the user's authenticator app and recovery codes.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	return nil
}

// VerifyResult tells the caller whether the supplied code matched a TOTP
// or a recovery code. The handler audits accordingly.
type VerifyResult struct {
	UsedRecoveryCode bool
	RecoveryCodeID   *uuid.UUID
}

// Verify accepts a TOTP code or a one-time recovery code. Recovery codes
// are consumed on use. The caller passes a tx so the consumption and any
// audit row commit together.
func (s *Service) Verify(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) (*VerifyResult, error) {
	userID := attempt.userID
	result, err := s.verifyCode(ctx, tx, userID, code)
	if err != nil {
		if errors.Is(err, errs.ErrMFACodeInvalid) {
			return nil, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
		}
		return nil, err
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) verifyCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (*VerifyResult, error) {
	code = strings.TrimSpace(code)
	qtx := s.q.WithTx(tx)

	secret, confirmedAt, err := s.loadTOTP(ctx, tx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrMFANotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if !confirmedAt.Valid {
		return nil, errs.ErrMFANotConfirmed
	}
	if step, ok := totp.VerifyStep(secret, code); ok {
		fresh, cerr := consumeTOTPStep(ctx, tx, userID, step)
		if cerr != nil {
			return nil, cerr
		}
		if !fresh {
			// Already-used code. Reported as an ordinary invalid code so the
			// response does not distinguish "wrong" from "replayed".
			return nil, errs.ErrMFACodeInvalid
		}
		return &VerifyResult{}, nil
	}
	// Recovery code fallback.
	rcRows, err := qtx.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	var matchedID *uuid.UUID
	for _, rc := range rcRows {
		if password.Verify(rc.CodeHash, code) {
			matched := rc.ID
			matchedID = &matched
		}
	}
	if matchedID == nil {
		return nil, errs.ErrMFACodeInvalid
	}
	tag, err := tx.Exec(ctx, `
		UPDATE auth.mfa_recovery_codes SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL
	`, *matchedID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errs.ErrMFACodeInvalid
	}
	return &VerifyResult{UsedRecoveryCode: true, RecoveryCodeID: matchedID}, nil
}

// IsEnrolled reports whether the user has a confirmed authenticator app (TOTP).
// Other factor types are not considered.
func (s *Service) IsEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ts.Valid, nil
}

// VerifyForLoginTx checks an authenticator-app, recovery or email/SMS code for
// a sign-in's second step and returns which kind matched ("totp",
// "recovery_code" or "otp"). ("", nil) is a wrong or expired code; an error is
// an infrastructure failure.
func (s *Service) VerifyForLoginTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (string, error) {
	res, err := s.verifyCode(ctx, tx, userID, code)
	if err != nil {
		// A domain error (wrong/expired code, not-configured) means "not
		// verified" by the authenticator app or a recovery code — the code
		// may still be one sent to an email or SMS factor.
		if errs.As(err) == nil {
			return "", err
		}
		ok, oerr := s.verifyLoginOTP(ctx, tx, userID, code)
		if oerr != nil || !ok {
			return "", oerr
		}
		return "otp", nil
	}
	if res.UsedRecoveryCode {
		return "recovery_code", nil
	}
	return "totp", nil
}

// ResetForUser removes every second factor userID holds (authenticator app,
// recovery codes, email/SMS factors, push devices, pending push requests and
// unused pairing codes) and what they earned: trusted devices and step-ups.
// Passkeys stay. It returns the count removed per kind, for the audit record.
func (s *Service) ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int64, error) {
	removed := map[string]int64{}
	for _, step := range []struct {
		kind string
		sql  string
	}{
		{"totp", `DELETE FROM auth.mfa_totp WHERE user_id = $1`},
		{"recovery_codes", `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`},
		{"otp_factors", `DELETE FROM auth.mfa_otp_factors WHERE user_id = $1`},
		{"push_devices", `DELETE FROM auth.mfa_push_devices WHERE user_id = $1`},
		{"push_challenges", `DELETE FROM auth.mfa_push_challenges WHERE user_id = $1 AND status = 'pending'`},
		{"push_pairings", `DELETE FROM auth.mfa_push_pairings WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()`},
		{"trusted_devices", `DELETE FROM auth.trusted_devices WHERE user_id = $1`},
		{"step_ups", `DELETE FROM auth.mfa_verifications WHERE user_id = $1`},
	} {
		tag, err := tx.Exec(ctx, step.sql, userID)
		if err != nil {
			return nil, err
		}
		removed[step.kind] = tag.RowsAffected()
	}
	return removed, nil
}
