package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// The second factor of a sign-in (auth.MFAEnroller): every factor a person has
// confirmed can be challenged — an authenticator app (with its recovery codes),
// email and SMS code factors, passkeys while their organisation allows them,
// and push devices — not only the authenticator app.

// SetWebAuthn wires passkey assertions as a sign-in second factor (nil:
// passkeys are not offered as one). Called from internal/bootstrap.
func (s *Service) SetWebAuthn(v WebAuthnVerifier) { s.webauthn = v }

// LoginFactors lists the second factors userID can meet a sign-in challenge
// with, in a stable order.
func (s *Service) LoginFactors(ctx context.Context, userID uuid.UUID) ([]auth.LoginFactor, error) {
	counts, err := s.q.LoginFactorCounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []auth.LoginFactor
	if counts.Totp {
		out = append(out, auth.LoginFactor{Type: "totp"})
	}
	if counts.RecoveryCodes > 0 {
		out = append(out, auth.LoginFactor{Type: "recovery_code"})
	}
	factors, err := s.q.ListOTPFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, f := range factors {
		if !f.VerifiedAt.Valid {
			continue
		}
		id := f.ID
		out = append(out, auth.LoginFactor{Type: f.Channel, ID: &id, Destination: maskDestination(f.Channel, f.Destination)})
	}
	if counts.Passkeys > 0 && s.webauthn != nil {
		out = append(out, auth.LoginFactor{Type: "passkey"})
	}
	if counts.PushDevices > 0 {
		out = append(out, auth.LoginFactor{Type: "push"})
	}
	return out, nil
}

// SendLoginCode sends a sign-in code to one of the user's confirmed email or
// SMS factors.
func (s *Service) SendLoginCode(ctx context.Context, userID, factorID uuid.UUID) error {
	return s.ChallengeOTP(ctx, userID, factorID)
}

// verifyLoginOTP consumes an email/SMS code of the user's inside tx; false
// when no live code matches.
func (s *Service) verifyLoginOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (bool, error) {
	codeID, err := s.q.WithTx(tx).GetOTPCodeForVerify(ctx, dbgen.GetOTPCodeForVerifyParams{
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// BeginLoginPasskey starts a passkey assertion for userID's own passkeys.
func (s *Service) BeginLoginPasskey(ctx context.Context, userID uuid.UUID) (uuid.UUID, any, error) {
	if s.webauthn == nil {
		return uuid.Nil, nil, errs.ErrMFAWebAuthnUnavailable
	}
	id, options, err := s.webauthn.BeginMFA(ctx, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options.Response, nil
}

// FinishLoginPasskey verifies an assertion for the ceremony begun by
// BeginLoginPasskey.
func (s *Service) FinishLoginPasskey(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	if s.webauthn == nil {
		return errs.ErrMFAWebAuthnUnavailable
	}
	return s.webauthn.FinishMFA(ctx, userID, sessionID, credential)
}

// StartLoginPush sends a sign-in approval request to every push device of the
// user and returns the request's id and expiry.
func (s *Service) StartLoginPush(ctx context.Context, userID uuid.UUID, ip, ua string) (uuid.UUID, time.Time, error) {
	id, err := s.CreatePushChallenge(ctx, userID, "sign_in", PushChallengeContext{
		IP: ip, UserAgent: ua, Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	ch, err := s.GetPushChallenge(ctx, id)
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	return id, ch.ExpiresAt, nil
}

// LoginPushStatusTx reads the state of one of userID's push requests under
// lock: "pending", "approved", "denied" or "expired" (a pending request past
// its expiry reads expired).
func (s *Service) LoginPushStatusTx(ctx context.Context, tx pgx.Tx, userID, challengeID uuid.UUID) (string, error) {
	row, err := s.q.WithTx(tx).PushChallengeForLogin(ctx, dbgen.PushChallengeForLoginParams{ID: challengeID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "expired", nil
	}
	if err != nil {
		return "", err
	}
	if row.Status == "pending" && time.Now().After(row.ExpiresAt) {
		return "expired", nil
	}
	return row.Status, nil
}

// StartLoginEnrollment starts an authenticator app for a sign-in's enrolment
// challenge (the account must have a second factor and holds none), inside
// the challenge transaction. Returns the secret and provisioning URL.
func (s *Service) StartLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (string, string, error) {
	e, err := s.StartEnroll(ctx, tx, userID, account)
	if err != nil {
		return "", "", err
	}
	return e.Secret, e.ProvisioningURL, nil
}

// ConfirmLoginEnrollment confirms the authenticator app started for a
// sign-in's enrolment challenge with a code from it, inside the challenge
// transaction, and returns the account's new recovery codes. (nil, false,
// nil) is a wrong code, counted by the challenge.
func (s *Service) ConfirmLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, bool, error) {
	return s.confirmTOTP(ctx, tx, userID, code)
}
