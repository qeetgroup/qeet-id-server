package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// When an account holds a confirmed second factor, password sign-in returns a
// challenge listing those factors. It is met by a code, a passkey assertion
// (BeginMFAPasskey) or an approved push (StartMFAPush); both ceremonies are bound
// to the challenge, so they can't complete another sign-in.

// LoginFactor is one way a person can meet a sign-in's second-factor
// challenge.
type LoginFactor struct {
	// Type is "totp", "recovery_code", "email", "sms", "passkey" or "push".
	Type string `json:"type"`
	// ID names an email or SMS factor, for SendMFACode.
	ID *uuid.UUID `json:"id,omitempty"`
	// Destination is an email or SMS factor's masked address or number.
	Destination string `json:"destination,omitempty"`
}

// Body is the challenge as the client sees it. An enrolment challenge (the
// account must set up a factor and holds none) adds enrollment_required, and
// enrollment_due_at while the setup may be skipped.
func (c MFAChallenge) Body() map[string]any {
	body := map[string]any{
		"mfa_required": true,
		"mfa_token":    c.MFAToken,
		"methods":      c.Methods,
		"factors":      c.Factors,
	}
	if c.EnrollmentRequired {
		body["enrollment_required"] = true
		if c.EnrollmentDueAt != nil {
			body["enrollment_due_at"] = c.EnrollmentDueAt
		}
	}
	return body
}

// methodsOf is the distinct factor types, in order — the challenge's methods.
func methodsOf(factors []LoginFactor) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range factors {
		if !seen[f.Type] {
			seen[f.Type] = true
			out = append(out, f.Type)
		}
	}
	return out
}

// MFAProof is how a challenge is met: exactly one of a code, a passkey
// assertion, or an approved push. An enrolment challenge (see mfapolicy.go)
// is met by a code from the authenticator app set up for it, or skipped
// while the organisation's grace period runs.
type MFAProof struct {
	Code    string
	Passkey *PasskeyProof
	Push    bool
	Skip    bool
}

// kind names the proof as audited: "enrollment" for the code confirming an
// authenticator app set up for an enrolment challenge.
func (p MFAProof) kind(enrollment bool) string {
	switch {
	case enrollment:
		return "enrollment"
	case p.Passkey != nil:
		return "passkey"
	case p.Push:
		return "push"
	default:
		return "code"
	}
}

// PasskeyProof is a passkey assertion for the ceremony begun for a challenge.
type PasskeyProof struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// maxMFACodesSent bounds the email/SMS codes one challenge may send.
const maxMFACodesSent = 5

// errNotAFactorChallenge refuses a factor's helper (a code sent, a passkey
// ceremony, a push request) for an enrolment challenge, which holds none.
var errNotAFactorChallenge = errs.ErrBadRequest.WithDetail("This sign-in is setting up a second factor; it has none to use yet.")

// pendingMFAChallenge is a challenge not yet met, as its helpers read it.
type pendingMFAChallenge struct {
	userID           uuid.UUID
	tenantID         *uuid.UUID
	enrollment       bool
	passkeySessionID *uuid.UUID
	pushChallengeID  *uuid.UUID
	codesSent        int32
	// riskEmail: met by a code to the verified email (see risksignin.go);
	// emailCodeSentAt is when the last one went.
	riskEmail       bool
	emailCodeSentAt *time.Time
}

// loadMFAChallenge reads a live challenge under lock: ErrAuthSessionInvalid
// for a malformed token, ErrAuthMFAChallengeExpired for an unknown or expired
// one.
func loadMFAChallenge(ctx context.Context, tx pgx.Tx, mfaToken string) (uuid.UUID, pendingMFAChallenge, error) {
	id, err := uuid.Parse(mfaToken)
	if err != nil {
		return uuid.Nil, pendingMFAChallenge{}, errs.ErrAuthSessionInvalid
	}
	var c pendingMFAChallenge
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, enrollment, expires_at, passkey_session_id, push_challenge_id, codes_sent,
		       risk_email, email_code_sent_at
		FROM auth.mfa_login_challenges WHERE id = $1 FOR UPDATE`, id).
		Scan(&c.userID, &c.tenantID, &c.enrollment, &expiresAt, &c.passkeySessionID, &c.pushChallengeID, &c.codesSent,
			&c.riskEmail, &c.emailCodeSentAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(expiresAt)) {
		return uuid.Nil, pendingMFAChallenge{}, errs.ErrAuthMFAChallengeExpired
	}
	return id, c, err
}

// withMFAChallenge runs fn on the live challenge mfaToken names, in one
// transaction committed when fn succeeds.
func (s *Service) withMFAChallenge(ctx context.Context, mfaToken string, fn func(tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error) error {
	if s.mfa == nil {
		return errs.ErrNotImplemented
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	id, c, err := loadMFAChallenge(ctx, tx, mfaToken)
	if err != nil {
		return err
	}
	if err := fn(tx, id, c); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SendMFACode sends a code to one of the challenged person's email or SMS
// factors, at most maxMFACodesSent times per challenge.
func (s *Service) SendMFACode(ctx context.Context, mfaToken string, factorID uuid.UUID) error {
	return s.withMFAChallenge(ctx, mfaToken, func(tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error {
		if c.enrollment {
			return errNotAFactorChallenge
		}
		if c.codesSent >= maxMFACodesSent {
			return errs.ErrTooManyRequests
		}
		if c.riskEmail {
			// The one factor a risk challenge offers is the verified email,
			// named by the challenge itself.
			if factorID != id {
				return errs.ErrNotFound
			}
			return s.sendRiskEmailCode(ctx, tx, id, c)
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET codes_sent = codes_sent + 1 WHERE id = $1`, id); err != nil {
			return err
		}
		return s.mfa.SendLoginCode(ctx, c.userID, c.tenantID, factorID)
	})
}

// BeginMFAPasskey starts the passkey ceremony for the challenge and returns
// its id and assertion options; only an assertion from it meets the challenge.
func (s *Service) BeginMFAPasskey(ctx context.Context, mfaToken string) (uuid.UUID, any, error) {
	var sessionID uuid.UUID
	var options any
	err := s.withMFAChallenge(ctx, mfaToken, func(tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error {
		if c.enrollment || c.riskEmail {
			return errNotAFactorChallenge
		}
		var err error
		if sessionID, options, err = s.mfa.BeginLoginPasskey(ctx, c.userID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET passkey_session_id = $2 WHERE id = $1`, id, sessionID)
		return err
	})
	return sessionID, options, err
}

// StartMFAPush sends a push approval request for the challenge to the
// person's devices and returns when it expires; only its approval meets the
// challenge.
func (s *Service) StartMFAPush(ctx context.Context, mfaToken, ip, ua string) (time.Time, error) {
	var expires time.Time
	err := s.withMFAChallenge(ctx, mfaToken, func(tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error {
		if c.enrollment || c.riskEmail {
			return errNotAFactorChallenge
		}
		pushID, exp, err := s.mfa.StartLoginPush(ctx, c.userID, ip, ua)
		if err != nil {
			return err
		}
		expires = exp
		_, err = tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET push_challenge_id = $2 WHERE id = $1`, id, pushID)
		return err
	})
	return expires, err
}

// verifyMFAProof checks proof against the challenge inside tx and returns the
// factor type that met it ("webauthn", "push", or a code's kind). ("", nil) is
// a wrong proof, counted as a failed attempt; errs.ErrMFAPushPending is not.
func (s *Service) verifyMFAProof(ctx context.Context, tx pgx.Tx, userID uuid.UUID, passkeySession, pushChallenge *uuid.UUID, proof MFAProof) (string, error) {
	switch {
	case proof.Passkey != nil:
		if passkeySession == nil || *passkeySession != proof.Passkey.SessionID {
			return "", nil
		}
		if err := s.mfa.FinishLoginPasskey(ctx, userID, proof.Passkey.SessionID, proof.Passkey.Credential); err != nil {
			if errs.As(err) != nil {
				return "", nil
			}
			return "", err
		}
		return "webauthn", nil
	case proof.Push:
		if pushChallenge == nil {
			return "", nil
		}
		status, err := s.mfa.LoginPushStatusTx(ctx, tx, userID, *pushChallenge)
		if err != nil {
			return "", err
		}
		switch status {
		case "approved":
			return "push", nil
		case "pending":
			return "", errs.ErrMFAPushPending
		case "expired":
			return "", errs.ErrMFAPushChallengeExpired
		default:
			return "", nil
		}
	default:
		return s.mfa.VerifyForLoginTx(ctx, tx, userID, proof.Code)
	}
}
