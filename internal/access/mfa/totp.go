package mfa

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// consumeTOTPStep marks a TOTP time step used, returning false if that step or
// a later one already was. A code is accepted for about 90s, so this stops one
// code authenticating twice (RFC 6238 §5.2); a single conditional UPDATE lets
// only one of two concurrent submissions win.
func consumeTOTPStep(ctx context.Context, tx pgx.Tx, userID uuid.UUID, step int64) (bool, error) {
	n, err := dbgen.New(tx).ConsumeTOTPStep(ctx, dbgen.ConsumeTOTPStepParams{UserID: userID, Step: &step})
	return n == 1, err
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

// StartEnroll starts setting up an authenticator app for userID, named account in the app, recorded
// as by's. While the account holds a confirmed app the new one waits beside it (pending_secret_*)
// until a code confirms it, so starting a setup never switches the working app off; one unconfirmed
// for pendingTOTPTTL is ignored.
func (s *Service) StartEnroll(ctx context.Context, userID uuid.UUID, account string, by Caller) (*Enrollment, error) {
	var out *Enrollment
	err := s.inTx(ctx, func(tx pgx.Tx) (err error) {
		if out, err = s.startEnroll(ctx, tx, userID, account); err != nil {
			return err
		}
		return audit.Record(ctx, tx, by.event("mfa.totp_enroll_started", userID, map[string]any{"replacing": out.Replacing}))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// startEnroll is StartEnroll inside tx, unaudited.
func (s *Service) startEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (*Enrollment, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-totp", userID.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	q := s.q.WithTx(tx)
	replacing, err := q.LockTOTPConfirmed(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if replacing {
		err = q.StagePendingTOTP(ctx, dbgen.StagePendingTOTPParams{UserID: userID, PendingSecretCt: ciphertext, PendingSecretNonce: nonce})
	} else {
		err = q.StartTOTP(ctx, dbgen.StartTOTPParams{UserID: userID, SecretCt: ciphertext, SecretNonce: nonce})
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

// ConfirmEnroll completes userID's authenticator-app enrolment with a code from
// the app, recorded as by's, and returns the new recovery codes. Proving the
// app steps up by's session, so its next sensitive action needs no second
// code. Each try spends one of the person's setup attempts.
func (s *Service) ConfirmEnroll(ctx context.Context, userID uuid.UUID, code string, by Caller) ([]string, error) {
	var minted []string
	err := s.withAttempt(ctx, userID, PurposeTOTPEnroll, func(attempt Attempt) error {
		return s.inTx(ctx, func(tx pgx.Tx) (err error) {
			if minted, err = s.confirmEnroll(ctx, tx, attempt, code); err != nil {
				return err
			}
			if err := s.recordStepUp(ctx, tx, userID, by, "totp"); err != nil {
				return err
			}
			return audit.Record(ctx, tx, by.event("mfa.totp_enrolled", userID, map[string]any{"recovery_codes_minted": len(minted)}))
		})
	})
	if err != nil {
		return nil, err
	}
	return minted, nil
}

// confirmEnroll is ConfirmEnroll inside tx with a reserved attempt, unaudited.
func (s *Service) confirmEnroll(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) ([]string, error) {
	codes, ok, err := s.confirmTOTP(ctx, tx, attempt.userID, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, attemptError(ErrTOTPCodeInvalid, attempt.remaining)
	}
	return codes, nil
}

// confirmTOTP confirms the authenticator app being set up with a code from
// it and mints fresh recovery codes. (nil, false, nil) is a wrong code. A
// replacement replaces the confirmed app only here, once its code is right.
func (s *Service) confirmTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, bool, error) {
	qtx := s.q.WithTx(tx)
	setup, err := qtx.LockTOTPSetup(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errs.ErrMFAEnrollNotStarted
	}
	if err != nil {
		return nil, false, err
	}
	if setup.PendingSecretCt != nil {
		return s.confirmReplacementTOTP(ctx, tx, userID, code, setup.PendingSecretCt, setup.PendingSecretNonce, postgres.ZeroIfNull(setup.PendingStartedAt))
	}
	if setup.Confirmed {
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
	plain, err := s.box.Open(userID, "mfa-totp", userID.String(), ct, nonce)
	if err != nil {
		return nil, false, err
	}
	step, ok := totp.VerifyStep(string(plain), code)
	if !ok {
		return nil, false, nil
	}
	if err := s.q.WithTx(tx).PromotePendingTOTP(ctx, dbgen.PromotePendingTOTPParams{UserID: userID, Step: &step}); err != nil {
		return nil, false, err
	}
	if err := clearMFAAttempt(ctx, tx, userID, PurposeTOTPEnroll); err != nil {
		return nil, false, err
	}
	codes, err := s.mintRecoveryCodes(ctx, tx, userID)
	return codes, err == nil, err
}

func (s *Service) loadTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, *time.Time, error) {
	row, err := s.q.WithTx(tx).GetTOTPSecret(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	plain, err := s.box.Open(userID, "mfa-totp", userID.String(), row.SecretCt, row.SecretNonce)
	return string(plain), row.ConfirmedAt, err
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
	return &TOTPStatus{Enrolled: err == nil && ts != nil}, nil
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
	st.Enrolled = err == nil && ts != nil
	stats, err := s.q.GetMFARecoveryCodeStats(ctx, userID)
	if err != nil {
		return nil, err
	}
	st.Total = int(stats.Total)
	st.Remaining = int(stats.Remaining)
	return &st, nil
}

// Regenerate issues userID a fresh set of recovery codes, invalidating the old
// set, recorded as by's. Requires confirmed TOTP — recovery codes are a backup
// for an enrolled factor.
func (s *Service) Regenerate(ctx context.Context, userID uuid.UUID, by Caller) ([]string, error) {
	var out []string
	err := s.inTx(ctx, func(tx pgx.Tx) (err error) {
		if out, err = s.regenerate(ctx, tx, userID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, by.event("mfa.recovery_codes_regenerated", userID, map[string]any{"count": len(out)}))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// regenerate is Regenerate inside tx, unaudited.
func (s *Service) regenerate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	ts, err := s.q.WithTx(tx).GetMFATOTPConfirmed(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if ts == nil {
		return nil, ErrNotConfirmed
	}
	return s.mintRecoveryCodes(ctx, tx, userID)
}

// Disable removes userID's authenticator app and recovery codes, recorded as
// by's.
func (s *Service) Disable(ctx context.Context, userID uuid.UUID, by Caller) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := s.disable(ctx, tx, userID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, by.event("mfa.totp_disabled", userID, nil))
	})
}

// disable is Disable inside tx, unaudited.
func (s *Service) disable(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
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
// or a recovery code.
type VerifyResult struct {
	UsedRecoveryCode bool
	RecoveryCodeID   *uuid.UUID
}

// Verify accepts a TOTP code or a one-time recovery code of userID's and steps
// up by's session by the factor met. A recovery code is consumed on use and
// recorded as by's; an authenticator code, used far more often, is not
// recorded. Each try spends one of the person's verification attempts.
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, code string, by Caller) (*VerifyResult, error) {
	var result *VerifyResult
	err := s.withAttempt(ctx, userID, PurposeFactorVerify, func(attempt Attempt) error {
		return s.inTx(ctx, func(tx pgx.Tx) (err error) {
			if result, err = s.verify(ctx, tx, attempt, code); err != nil {
				return err
			}
			method := "totp"
			if result.UsedRecoveryCode {
				method = "recovery_code"
			}
			if err := s.recordStepUp(ctx, tx, userID, by, method); err != nil || !result.UsedRecoveryCode {
				return err
			}
			meta := map[string]any{}
			if result.RecoveryCodeID != nil {
				meta["recovery_code_id"] = *result.RecoveryCodeID
			}
			return audit.Record(ctx, tx, by.event("mfa.recovery_code_used", userID, meta))
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// verify is Verify inside tx with a reserved attempt, unaudited.
func (s *Service) verify(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) (*VerifyResult, error) {
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
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if confirmedAt == nil {
		return nil, ErrNotConfirmed
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
		ok, err := password.VerifyWithin(ctx, rc.CodeHash, code)
		if err != nil {
			return nil, err
		}
		if ok {
			matched := rc.ID
			matchedID = &matched
		}
	}
	if matchedID == nil {
		return nil, errs.ErrMFACodeInvalid
	}
	n, err := qtx.MarkRecoveryCodeUsed(ctx, *matchedID)
	if err != nil {
		return nil, err
	}
	if n != 1 {
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
	return ts != nil, nil
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
// It lifts a lock of their second-factor sign-in. Passkeys stay. It returns the count removed per kind, for the audit record.
func (s *Service) ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int64, error) {
	q := s.q.WithTx(tx)
	removed := map[string]int64{}
	for _, step := range []struct {
		kind  string
		reset func(context.Context, uuid.UUID) (int64, error)
	}{
		{"totp", q.ResetTOTP},
		{"recovery_codes", q.ResetRecoveryCodes},
		{"otp_factors", q.ResetOTPFactors},
		{"push_devices", q.ResetPushDevices},
		{"push_challenges", q.ResetPendingPushChallenges},
		{"push_pairings", q.ResetLivePushPairings},
		{"trusted_devices", q.ResetTrustedDevices},
		{"step_ups", q.ResetStepUps},
		{"failure_streaks", q.ResetFailureStreaks},
	} {
		n, err := step.reset(ctx, userID)
		if err != nil {
			return nil, err
		}
		removed[step.kind] = n
	}
	return removed, nil
}
