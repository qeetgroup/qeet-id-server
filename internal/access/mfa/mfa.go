// Package mfa implements TOTP enrollment and verification plus a small
// set of recovery codes. Recovery codes are bcrypt-hashed; the user sees
// the plaintext list exactly once at generation.
//
// Mutating methods take a pgx.Tx so the caller (HTTP handler) can wrap
// the mutation plus its audit row in a single transaction.
package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

type Service struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	issuer  string // "qeet-id" — shown in the authenticator app
	sender  notifier.Sender
	pushURL string // Expo push API endpoint ("" = push delivery off)
	// pushAccessToken is sent to the push service when set (SetExpoAccessToken).
	pushAccessToken string
	box             *envelope.Cipher
	// webauthn asserts passkeys as a sign-in second factor (nil = not
	// offered). Set via SetWebAuthn; see login.go.
	webauthn WebAuthnVerifier
	// plan gates SMS codes by the organisation's plan (nil = no gate). Set via
	// SetPlan.
	plan PlanGate
	// deliverable reports whether a channel can reach anyone (nil: assume it
	// can). Set via SetDeliveryCheck.
	deliverable func(channel string) bool
}

func NewService(pool *pgxpool.Pool, issuer string, sender notifier.Sender, pushURL string) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, sender: sender, pushURL: pushURL}
}

func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetPlan wires the plan gate for SMS codes, a paid feature (it also costs per
// message): every SMS code, at setup, step-up and sign-in, is refused unless
// the organisation's plan includes sms_mfa, and refused outright with no
// organisation.
func (s *Service) SetPlan(p PlanGate) { s.plan = p }

// SetDeliveryCheck wires the check that a channel can deliver a code
// (notifier.Router.Configured). A code for a channel that cannot is refused
// with ErrMFADeliveryUnavailable before anything is stored.
func (s *Service) SetDeliveryCheck(deliverable func(channel string) bool) {
	s.deliverable = deliverable
}

// consumeTOTPStep atomically marks a TOTP time-step as used, returning false if
// that step (or a later one) was already consumed.
//
// totp.Verify accepts the current 30s step plus one either side, so without
// this a correct code remained valid for ~90s and could be presented twice for
// two independent authentications — the replay RFC 6238 §5.2 requires us to
// reject. The check and the write are a single conditional UPDATE so two
// concurrent submissions of the same code cannot both win: exactly one updates
// a row, the other sees RowsAffected() == 0.
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

const otpTTL = 10 * time.Minute

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an MFA mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type Enrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
	// Replacing: the account holds a confirmed app, which keeps working
	// until a code from this one confirms it.
	Replacing bool `json:"replacing"`
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
// returns the plaintext exactly once; only the bcrypt hashes are persisted.
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

// TOTPStatus reports whether the account has a *confirmed* TOTP factor. The
// account UI reads this on load to render an "active" state instead of
// re-offering enrollment. A new setup started while one is confirmed waits
// beside it and does not change this until it is confirmed.
type TOTPStatus struct {
	Enrolled bool `json:"enrolled"`
}

func (s *Service) TOTPStatus(ctx context.Context, userID uuid.UUID) (*TOTPStatus, error) {
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return &TOTPStatus{Enrolled: err == nil && ts.Valid}, nil
}

// RecoveryStatus summarises a user's backup codes for the account UI.
type RecoveryStatus struct {
	Enrolled  bool `json:"enrolled"` // TOTP confirmed — recovery codes back a real factor
	Total     int  `json:"total"`
	Remaining int  `json:"remaining"`
}

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

// IsEnrolled reports whether the user has a second factor that can satisfy the
// login MFA step today: a confirmed TOTP factor (recovery codes back it). The
// auth package consults this (via the MFAEnroller interface) to decide whether
// to challenge for a second factor at login.
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

// VerifyForLoginTx verifies an authenticator-app, recovery or email/SMS code as
// the second step of login and returns which kind met it ("totp",
// "recovery_code" or "otp"), so the session the sign-in opens can be recorded
// as stepped up. ("", nil) is a wrong or expired code; a non-nil error is an
// infrastructure failure.
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

// ResetForUser clears every second factor a user holds — the authenticator
// app, recovery codes, email/SMS factors (their codes cascade), push devices
// and their pending approval requests — together with what a factor earned:
// remembered devices and step-ups. Passkeys stay: they are how the person signs
// in, and are managed on their own. It returns how many of each it removed,
// keyed by kind, for the audit record. This is an admin account-recovery
// operation (a user locked out of their authenticator); the caller wraps it and
// its audit row in one transaction.
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

// Email / SMS OTP factors

// OTPFactor is the account-facing view of a registered OTP channel. The
// destination is masked so the UI can show which factor without exposing the
// full address/number.
type OTPFactor struct {
	ID          uuid.UUID `json:"id"`
	Channel     string    `json:"channel"`
	Destination string    `json:"destination"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
}

func maskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at <= 1 {
			return dest
		}
		return dest[:1] + strings.Repeat("*", at-1) + dest[at:]
	}
	// phone: keep the last 3 digits.
	if len(dest) <= 3 {
		return dest
	}
	return strings.Repeat("*", len(dest)-3) + dest[len(dest)-3:]
}

// sendOTP generates a code for the factor, persists its hash, and dispatches
// the plaintext via the configured channel.
// Sending one-time codes is limited to the pace of a person asking for one, so
// the product cannot be driven to flood an inbox or a phone, or to bill the
// operator for text messages, and live codes do not pile up for one account.
const (
	// otpResendAfter: the wait before another code to the same factor.
	otpResendAfter = 30 * time.Second
	// otpSendsPerHourPerUser: codes one person may be sent in an hour, over
	// all their factors.
	otpSendsPerHourPerUser = 10
	// otpSendsPerHourPerDestination: codes one address or number may be sent
	// in an hour, over every account that holds it.
	otpSendsPerHourPerDestination = 5
	// maxOTPFactors: email and SMS factors one person may hold.
	maxOTPFactors = 5
)

// otpSend is one code to send: whose, in which organisation (nil: none; it
// decides whether SMS is in the plan), to which factor, and why ("enrollment",
// "step_up" or "sign_in", as audited).
type otpSend struct {
	userID      uuid.UUID
	tenantID    *uuid.UUID
	factorID    uuid.UUID
	channel     string
	destination string
	purpose     string
}

// sendOTP sends a fresh code to a factor. It is refused with
// ErrMFACodeSendLimited (retry_after: seconds) inside otpResendAfter of the
// factor's last code, or past the hourly limits; an SMS code is refused unless
// the organisation's plan includes it. The new code is the factor's only live
// one — earlier unused codes stop working — and the send is audited with the
// destination masked.
func (s *Service) sendOTP(ctx context.Context, in otpSend) error {
	if s.deliverable != nil && !s.deliverable(in.channel) {
		return errs.ErrMFADeliveryUnavailable.WithMetadata(map[string]any{"channel": in.channel})
	}
	if in.channel == "sms" && s.plan != nil {
		if in.tenantID == nil {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sms_mfa"})
		}
		ok, err := s.plan.FeatureAllowed(ctx, *in.tenantID, "sms_mfa")
		if err != nil {
			return err
		}
		if !ok {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sms_mfa"})
		}
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// One send at a time per factor, so two requests cannot both pass the wait.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.mfa_otp_factors WHERE id = $1 FOR UPDATE`, in.factorID); err != nil {
		return err
	}
	if wait, err := otpSendWait(ctx, tx, in); err != nil {
		return err
	} else if wait > 0 {
		return errs.ErrMFACodeSendLimited.WithMetadata(map[string]any{"retry_after": int(wait.Round(time.Second).Seconds())})
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_otp_codes SET expires_at = NOW()
		WHERE factor_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`, in.factorID); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).InsertMFAOTPCode(ctx, dbgen.InsertMFAOTPCodeParams{
		FactorID:  in.factorID,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(otpTTL),
	}); err != nil {
		return err
	}
	factor := in.factorID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     in.tenantID,
		ActorUserID:  &in.userID,
		ActorType:    "user",
		Action:       "mfa.otp_sent",
		ResourceType: "mfa_factor",
		ResourceID:   &factor,
		Metadata: map[string]any{"channel": in.channel, "destination": maskDestination(in.channel, in.destination),
			"purpose": in.purpose},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: in.channel,
		To:      in.destination,
		Subject: "Your verification code",
		Body:    fmt.Sprintf("Your %s sign-in code is %s. It expires in %s.", s.issuer, code, otpTTL),
	}); err != nil {
		s.undeliveredOTP(ctx, in, code)
		return errs.ErrMFADeliveryFailed.Wrap(err)
	}
	return nil
}

// undeliveredOTP withdraws a code the provider did not take, so it counts
// against no limit and can never be used, and audits the failure. Best effort:
// the caller already reports the failure.
func (s *Service) undeliveredOTP(ctx context.Context, in otpSend, code string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_otp_codes WHERE factor_id = $1 AND code_hash = $2`,
		in.factorID, codes.Hash(code)); err != nil {
		return
	}
	factor := in.factorID
	if audit.Record(ctx, tx, audit.Event{
		TenantID: in.tenantID, ActorUserID: &in.userID, ActorType: "user",
		Action: "mfa.otp_delivery_failed", ResourceType: "mfa_factor", ResourceID: &factor,
		Metadata: map[string]any{"channel": in.channel, "destination": maskDestination(in.channel, in.destination),
			"purpose": in.purpose},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// otpSendWait is how long until another code may go to in's factor: the rest
// of otpResendAfter since its last code, or until the oldest send counted
// against an hourly limit leaves the hour. Zero: one may go now.
func otpSendWait(ctx context.Context, tx pgx.Tx, in otpSend) (time.Duration, error) {
	var factorLast, userOldest, destOldest *time.Time
	var userHour, destHour int
	if err := tx.QueryRow(ctx, `
		SELECT
		    (SELECT max(c.created_at) FROM auth.mfa_otp_codes c WHERE c.factor_id = $1),
		    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.user_id = $2 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.user_id = $2 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.channel = $3 AND f.destination = $4 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.channel = $3 AND f.destination = $4 AND c.created_at > NOW() - INTERVAL '1 hour')
	`, in.factorID, in.userID, in.channel, in.destination).
		Scan(&factorLast, &userHour, &userOldest, &destHour, &destOldest); err != nil {
		return 0, err
	}
	var wait time.Duration
	later := func(d time.Duration) {
		if d > wait {
			wait = d
		}
	}
	if factorLast != nil {
		later(otpResendAfter - time.Since(*factorLast))
	}
	if userHour >= otpSendsPerHourPerUser && userOldest != nil {
		later(time.Hour - time.Since(*userOldest))
	}
	if destHour >= otpSendsPerHourPerDestination && destOldest != nil {
		later(time.Hour - time.Since(*destOldest))
	}
	if wait > 0 && wait < time.Second {
		wait = time.Second
	}
	return wait, nil
}

// EnrollOTPStart registers (or re-arms) a channel and sends a confirmation
// code. The factor is unverified until EnrollOTPConfirm succeeds. tenantID is
// the caller's organisation (nil: none), whose plan decides SMS. A person may
// hold at most maxOTPFactors email and SMS factors.
func (s *Service) EnrollOTPStart(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, channel, destination string) (uuid.UUID, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	destination = strings.TrimSpace(destination)
	if channel != "email" && channel != "sms" {
		return uuid.Nil, errs.ErrMFAChannelInvalid
	}
	if destination == "" {
		return uuid.Nil, errs.ErrMFADestinationRequired
	}
	if s.deliverable != nil && !s.deliverable(channel) {
		return uuid.Nil, errs.ErrMFADeliveryUnavailable.WithMetadata(map[string]any{"channel": channel})
	}
	var held int
	var already bool
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(bool_or(channel = $2 AND destination = $3), FALSE)
		FROM auth.mfa_otp_factors WHERE user_id = $1
	`, userID, channel, destination).Scan(&held, &already); err != nil {
		return uuid.Nil, err
	}
	if !already && held >= maxOTPFactors {
		return uuid.Nil, errs.ErrMFAFactorLimit
	}
	factorID, err := s.q.UpsertMFAOTPFactor(ctx, dbgen.UpsertMFAOTPFactorParams{
		UserID:      userID,
		Channel:     channel,
		Destination: destination,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.sendOTP(ctx, otpSend{userID: userID, tenantID: tenantID, factorID: factorID, channel: channel,
		destination: destination, purpose: "enrollment"}); err != nil {
		return uuid.Nil, err
	}
	return factorID, nil
}

// EnrollOTPConfirm verifies the code and marks the factor usable.
func (s *Service) EnrollOTPConfirm(ctx context.Context, tx pgx.Tx, attempt Attempt, factorID uuid.UUID, code string) error {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForConfirm(ctx, dbgen.GetOTPCodeForConfirmParams{
		ID:       factorID,
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return attemptError(errs.ErrMFAOTPCodeInvalid, attempt.remaining)
	}
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return attemptError(errs.ErrMFAOTPCodeInvalid, attempt.remaining)
	}
	if err := qtx.MarkOTPFactorVerified(ctx, factorID); err != nil {
		return err
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return err
	}
	return nil
}

func (s *Service) ListOTPFactors(ctx context.Context, userID uuid.UUID) ([]OTPFactor, error) {
	rows, err := s.q.ListOTPFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]OTPFactor, 0, len(rows))
	for _, m := range rows {
		out = append(out, OTPFactor{
			ID:          m.ID,
			Channel:     m.Channel,
			Destination: maskDestination(m.Channel, m.Destination),
			Verified:    m.VerifiedAt.Valid,
			CreatedAt:   m.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) DeleteOTPFactor(ctx context.Context, tx pgx.Tx, userID, factorID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteOTPFactor(ctx, dbgen.DeleteOTPFactorParams{
		ID:     factorID,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// ChallengeOTP sends a fresh code to a verified factor for a step-up. tenantID
// is the caller's organisation (nil: none), whose plan decides SMS.
func (s *Service) ChallengeOTP(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID) error {
	return s.challengeOTP(ctx, userID, tenantID, factorID, "step_up")
}

func (s *Service) challengeOTP(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID, purpose string) error {
	row, err := s.q.GetOTPFactorForChallenge(ctx, dbgen.GetOTPFactorForChallengeParams{
		ID:     factorID,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !row.VerifiedAt.Valid {
		return errs.ErrMFAFactorNotConfirmed
	}
	return s.sendOTP(ctx, otpSend{userID: userID, tenantID: tenantID, factorID: factorID, channel: row.Channel,
		destination: row.Destination, purpose: purpose})
}

// VerifyOTP consumes a code from any of the user's verified OTP factors.
func (s *Service) VerifyOTP(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) (bool, error) {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForVerify(ctx, dbgen.GetOTPCodeForVerifyParams{
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return false, err
	}
	return true, nil
}

// Step-up MFA
//
// A step-up proves something about one session: that it met a second factor
// recently. It is recorded against the session that earned it, so a factor
// proved in one browser never unlocks sensitive actions in another, and it
// ends with that session. Each organisation sets how long a step-up lasts
// (tenant.security_policies.step_up_window, 5 minutes by default) and which
// factor types count (step_up_methods, any by default). A changed password or
// an administrative factor reset clears every step-up the person holds.

// RecordVerification records that sessionID, one of userID's own live
// sessions, met a second factor by method ("totp", "recovery_code", "otp",
// "webauthn" or "push"). For any other session nothing is recorded, so the
// step-up stays unmet. Callers pass the tx the factor's own write runs in.
func (s *Service) RecordVerification(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, method string) error {
	return s.q.WithTx(tx).RecordStepUp(ctx, dbgen.RecordStepUpParams{
		Method:    method,
		SessionID: sessionID,
		UserID:    userID,
	})
}

// StepUp is a session's step-up as its organisation judges it.
type StepUp struct {
	// Met: the session met a counted factor within the window.
	Met bool
	// VerifiedAt and Method are the session's latest step-up, if any, whether
	// or not it still counts.
	VerifiedAt *time.Time
	Method     string
	// Window is how long a step-up lasts in the session's organisation, and
	// Methods the factor types it counts (nil: any).
	Window  time.Duration
	Methods []string
}

// StepUpState reads sessionID's step-up. A principal without a session (an API
// key, an agent, a hosted-login cookie) cannot step up: it reads as unmet.
func (s *Service) StepUpState(ctx context.Context, userID uuid.UUID, sessionID *uuid.UUID) (StepUp, error) {
	if sessionID == nil {
		return StepUp{Window: defaultStepUpWindow}, nil
	}
	row, err := s.q.StepUpState(ctx, dbgen.StepUpStateParams{SessionID: *sessionID, UserID: userID})
	if err != nil {
		return StepUp{}, err
	}
	st := StepUp{
		Met:     row.Fresh && row.MethodCounts,
		Window:  time.Duration(row.WindowSeconds) * time.Second,
		Methods: row.StepUpMethods,
	}
	if row.VerifiedAt.Valid {
		at := row.VerifiedAt.Time
		st.VerifiedAt = &at
	}
	if row.Method != nil {
		st.Method = *row.Method
	}
	if len(st.Methods) == 0 {
		st.Methods = nil
	}
	return st, nil
}

// defaultStepUpWindow is how long a step-up lasts where nothing else is known
// (no session): the organisation default the migration also uses.
const defaultStepUpWindow = 5 * time.Minute

// RequireRecentMFA gates a handler behind a step-up of the calling session:
// otherwise the request is refused with 403 step_up_required, listing the
// factor types that count (allowed_methods, omitted when any does), so the
// client can ask for one and retry. Both the refusal and a completed step-up
// are audited.
func RequireRecentMFA(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc.passStepUp(w, r) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// StepUpRule says when a route needs a step-up of the calling session.
type StepUpRule int

const (
	// StepUpAlways: every call needs one.
	StepUpAlways StepUpRule = iota + 1
	// StepUpWhenFactorHeld: a call needs one while the person holds a factor
	// their organisation counts for step-up. Setting up a first factor, or
	// changing factors while none can step up, needs none: there is nothing
	// to step up with.
	StepUpWhenFactorHeld
)

// StepUpGate refuses a call to a listed route ("METHOD /pattern", chi syntax)
// with 403 step_up_required unless the calling session is stepped up, as the
// route's rule says. Unlisted routes pass. Mount it on the authenticated group
// after authorization, so only an authorized caller is ever asked.
func (s *Service) StepUpGate(routes map[string]StepUpRule) func(http.Handler) http.Handler {
	always, whenHeld := chi.NewRouter(), chi.NewRouter()
	noop := func(http.ResponseWriter, *http.Request) {}
	for route, rule := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("mfa: step-up route without a method: " + route)
		}
		switch rule {
		case StepUpAlways:
			always.MethodFunc(method, pattern, noop)
		case StepUpWhenFactorHeld:
			whenHeld.MethodFunc(method, pattern, noop)
		default:
			panic("mfa: step-up route without a rule: " + route)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case always.Match(chi.NewRouteContext(), r.Method, r.URL.Path):
				if !s.passStepUp(w, r) {
					return
				}
			case whenHeld.Match(chi.NewRouteContext(), r.Method, r.URL.Path):
				if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.UserID != nil {
					held, err := s.HoldsStepUpFactor(r.Context(), *p.UserID, p.TenantID)
					if err != nil {
						httpx.WriteError(w, r, err)
						return
					}
					if held && !s.passStepUp(w, r) {
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HoldsStepUpFactor reports whether userID holds a factor that tenantID (nil:
// none) counts for a step-up, so a step-up can be asked of them.
func (s *Service) HoldsStepUpFactor(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) (bool, error) {
	tid := uuid.Nil
	if tenantID != nil {
		tid = *tenantID
	}
	row, err := s.q.StepUpFactorsHeld(ctx, dbgen.StepUpFactorsHeldParams{UserID: userID, TenantID: tid})
	if err != nil {
		return false, err
	}
	counts := func(methods ...string) bool {
		if len(row.StepUpMethods) == 0 {
			return true
		}
		for _, m := range methods {
			for _, allowed := range row.StepUpMethods {
				if m == allowed {
					return true
				}
			}
		}
		return false
	}
	return (row.Totp && counts("totp", "recovery_code")) || (row.Otp && counts("otp")) ||
		(row.Passkeys && counts("webauthn")), nil
}

// passStepUp reports whether the request's session is stepped up; when it is
// not, it has written the refusal (401 without a principal, else 403
// step_up_required) and audited it. A hosted-login principal holds no API
// session: its sign-in counts as a step-up for the organisation's window after
// it happened, where the organisation counts every factor type.
func (s *Service) passStepUp(w http.ResponseWriter, r *http.Request) bool {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return false
	}
	if p.SessionID == nil && p.SignedInAt != nil {
		tid := uuid.Nil
		if p.TenantID != nil {
			tid = *p.TenantID
		}
		org, err := s.q.OrgStepUpPolicy(r.Context(), tid)
		if err != nil {
			httpx.WriteError(w, r, err)
			return false
		}
		if org.EveryFactor && time.Since(*p.SignedInAt) <= time.Duration(org.WindowSeconds)*time.Second {
			return true
		}
	}
	st, err := s.StepUpState(r.Context(), *p.UserID, p.SessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return false
	}
	if !st.Met {
		s.auditStepUp(r, "mfa.step_up_required", map[string]any{"route": r.URL.Path})
		meta := map[string]any{"window_seconds": int(st.Window.Seconds())}
		if st.Methods != nil {
			meta["allowed_methods"] = st.Methods
		}
		httpx.WriteError(w, r, errs.ErrStepUpRequired.WithMetadata(meta))
		return false
	}
	return true
}

// auditStepUp records a step-up event for the request's principal in its own
// transaction. Best effort: the refusal or success it describes stands either
// way.
func (s *Service) auditStepUp(r *http.Request, action string, meta map[string]any) {
	ctx := r.Context()
	p := httpx.PrincipalFromCtx(ctx)
	if s.pool == nil {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	actorID, actorType := auditActor(r)
	if p.SessionID != nil {
		meta["session_id"] = *p.SessionID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "user",
		ResourceID:   p.UserID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// recordStepUp records, inside tx, that the calling session met a second
// factor by method and audits it there. A principal without a session has
// nothing to step up, so only the factor check itself counted.
func (h *Handler) recordStepUp(ctx context.Context, tx pgx.Tx, r *http.Request, method string) error {
	p := httpx.PrincipalFromCtx(ctx)
	if p == nil || p.UserID == nil || p.SessionID == nil {
		return nil
	}
	if err := h.Service.RecordVerification(ctx, tx, *p.UserID, *p.SessionID, method); err != nil {
		return err
	}
	actorID, actorType := auditActor(r)
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.step_up_verified",
		ResourceType: "user",
		ResourceID:   p.UserID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"method": method, "session_id": *p.SessionID},
	})
}

// WebAuthnVerifier asserts an already-authenticated user's existing passkey
// credentials as a second factor. It is satisfied by *passkey.Service; the
// interface lives here so package mfa can mount the routes without importing
// package passkey (which would create an import cycle — passkey already imports
// the lower-level platform packages mfa shares).
type WebAuthnVerifier interface {
	BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error)
	FinishMFA(ctx context.Context, userID, sessionID uuid.UUID, cred json.RawMessage) error
}

type Handler struct {
	Service *Service
	// WebAuthn, when set, exposes the user's registered passkeys as a second
	// factor (POST /mfa/webauthn/{challenge,verify}). Nil = feature disabled.
	WebAuthn WebAuthnVerifier
	// PairingThrottle, when set, wraps the public route a phone links with a
	// pairing code, which guesses at a code when the code is wrong.
	PairingThrottle func(http.Handler) http.Handler
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by operations/entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/mfa/totp", h.totpStatus)
	r.Post("/mfa/totp/enroll/start", h.startEnroll)
	r.Post("/mfa/totp/enroll/confirm", h.confirmEnroll)
	r.Post("/mfa/totp/verify", h.verify)
	r.Get("/mfa/recovery-codes", h.recoveryStatus)
	r.Get("/mfa/otp/factors", h.listOTPFactors)
	r.Post("/mfa/otp/factors", h.enrollOTPStart)
	r.Post("/mfa/otp/factors/{id}/confirm", h.enrollOTPConfirm)
	r.Post("/mfa/otp/factors/{id}/challenge", h.challengeOTP)
	r.Delete("/mfa/otp/factors/{id}", h.deleteOTPFactor)
	r.Post("/mfa/otp/verify", h.verifyOTP)

	// WebAuthn as a second factor: assert the user's existing passkeys.
	r.Post("/mfa/webauthn/challenge", h.webauthnChallenge)
	r.Post("/mfa/webauthn/verify", h.webauthnVerify)

	// Push authenticator device management (authenticated user).
	r.Get("/mfa/push/devices", h.listPushDevices)
	r.Post("/mfa/push/devices", h.registerPushDevice)
	r.Delete("/mfa/push/devices/{id}", h.revokePushDevice)
	// A pairing code links a phone without copying an access token.
	r.Post("/mfa/push/pairing", h.createPushPairing)
	r.Get("/mfa/push/pairing/{id}", h.getPushPairing)
	r.Delete("/mfa/push/pairing/{id}", h.withdrawPushPairing)

	// Step-up status — lets a client decide whether to prompt before a
	// sensitive action.
	r.Get("/mfa/step-up/status", h.stepUpStatus)

	// Sensitive MFA actions require a step-up of the calling session:
	// disabling MFA wholesale and regenerating recovery codes both invalidate a
	// user's standing factors, so gate them behind a fresh proof of possession.
	r.Group(func(r chi.Router) {
		r.Use(RequireRecentMFA(h.Service))
		r.Delete("/mfa/totp", h.disable)
		r.Post("/mfa/recovery-codes/regenerate", h.regenerateRecovery)
	})
}

// auditActor builds the actor portion of an audit row from the request
// principal. Returns ("", "system") for unauthenticated calls.
func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
}

type startEnrollInput struct {
	Account string `json:"account"`
}

func (h *Handler) startEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in startEnrollInput
	_ = httpx.DecodeJSON(r, &in)
	if in.Account == "" {
		in.Account = p.Subject
	}
	ctx := r.Context()
	// Setting up a new app replaces the confirmed one once confirmed, so while
	// one is held this needs the same step-up as switching it off. A first
	// setup needs none: there is no factor to step up with yet.
	enrolled, err := h.Service.IsEnrolled(ctx, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if enrolled && !h.Service.passStepUp(w, r) {
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	out, err := h.Service.StartEnroll(ctx, tx, *p.UserID, in.Account)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	tenantID := p.TenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enroll_started",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"replacing": out.Replacing},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type confirmEnrollInput struct {
	Code string `json:"code"`
}

func (h *Handler) confirmEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in confirmEnrollInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeTOTPEnroll)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Registered before the transaction below so the refund only takes a
	// connection once that transaction has released its own — see Attempt.
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var codes []string
	codes, opErr = h.Service.ConfirmEnroll(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// Confirming the app proves possession of it, so the session that did it
	// is stepped up: the next sensitive action (regenerate recovery codes,
	// disable the app) needs no second code.
	if opErr = h.recordStepUp(ctx, tx, r, "totp"); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enrolled",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"recovery_codes_minted": len(codes)},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": codes,
		"warning":        "store these once; they will not be shown again",
	})
}

type verifyInput struct {
	Code string `json:"code"`
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeFactorVerify)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var result *VerifyResult
	result, opErr = h.Service.Verify(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// The calling session is stepped up by the factor it just met.
	method := "totp"
	if result.UsedRecoveryCode {
		method = "recovery_code"
	}
	if opErr = h.recordStepUp(ctx, tx, r, method); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// Only audit when a recovery code was consumed — every successful
	// TOTP verify is high-frequency and not interesting for the chain.
	if result.UsedRecoveryCode {
		actorID, actorType := auditActor(r)
		target := *p.UserID
		meta := map[string]any{}
		if result.RecoveryCodeID != nil {
			meta["recovery_code_id"] = *result.RecoveryCodeID
		}
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID:     p.TenantID,
			ActorUserID:  actorID,
			ActorType:    actorType,
			Action:       "mfa.recovery_code_used",
			ResourceType: "user",
			ResourceID:   &target,
			IP:           httpx.ClientIP(r),
			UserAgent:    r.UserAgent(),
			RequestID:    httpx.RequestID(r),
			Metadata:     meta,
		}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Disable(ctx, tx, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_disabled",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) totpStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.TOTPStatus(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.RecoveryStatus(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) regenerateRecovery(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	out, err := h.Service.Regenerate(ctx, tx, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.recovery_codes_regenerated",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"count": len(out)},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": out,
		"warning":        "store these once; they will not be shown again",
	})
}

// --- OTP factor handlers ---

type enrollOTPInput struct {
	Channel     string `json:"channel"`
	Destination string `json:"destination"`
}

func (h *Handler) listOTPFactors(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListOTPFactors(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) enrollOTPStart(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in enrollOTPInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// SMS is a paid factor: the service refuses it unless the caller's
	// organisation's plan includes it (see SetPlan).
	factorID, err := h.Service.EnrollOTPStart(r.Context(), *p.UserID, p.TenantID, in.Channel, in.Destination)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"factor_id": factorID, "message": "verification code sent"})
}

func (h *Handler) enrollOTPConfirm(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeOTPEnroll(factorID))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	if opErr = h.Service.EnrollOTPConfirm(ctx, tx, attempt, factorID, in.Code); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.otp_factor_added",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) challengeOTP(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.ChallengeOTP(r.Context(), *p.UserID, p.TenantID, factorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"message": "verification code sent"})
}

func (h *Handler) deleteOTPFactor(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.DeleteOTPFactor(ctx, tx, *p.UserID, factorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.otp_factor_removed",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) verifyOTP(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeOTPVerify)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var ok bool
	ok, opErr = h.Service.VerifyOTP(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	if !ok {
		httpx.WriteError(w, r, errs.ErrMFACodeInvalid)
		return
	}
	if opErr = h.recordStepUp(ctx, tx, r, "otp"); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	if opErr = tx.Commit(ctx); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// --- WebAuthn second-factor handlers ---

func (h *Handler) webauthnChallenge(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, errs.ErrMFAWebAuthnUnavailable)
		return
	}
	sessionID, options, err := h.WebAuthn.BeginMFA(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type webauthnVerifyInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

func (h *Handler) webauthnVerify(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, errs.ErrMFAWebAuthnUnavailable)
		return
	}
	var in webauthnVerifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.WebAuthn.FinishMFA(ctx, *p.UserID, in.SessionID, in.Credential); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// FinishMFA has no surrounding tx (the assertion verify already committed its
	// sign-count update), so record the step-up + audit in their own tx.
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.recordStepUp(ctx, tx, r, "webauthn"); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.webauthn_verified",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// --- Step-up status ---

func (h *Handler) stepUpStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.StepUpState(r.Context(), *p.UserID, p.SessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recently_verified": st.Met,
		"verified_at":       st.VerifiedAt,
		"window_seconds":    int(st.Window.Seconds()),
		"allowed_methods":   st.Methods,
	})
}
