package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SwitchTenantInput names who switches, from which of their sessions, and to
// which organization. FromSessionID must come from the caller's own access
// token, never from anything the client supplies.
type SwitchTenantInput struct {
	UserID        uuid.UUID
	FromSessionID uuid.UUID
	TenantID      uuid.UUID
	IP            string
	UserAgent     string
}

// SwitchTenant replaces the caller's session with one in another organisation
// they belong to, ending the old one in the same transaction. The organisation's
// second-factor requirement must already be met (ErrStepUpRequired,
// ErrMFAEnrollmentRequired); on any refusal nothing changes.
func (s *Service) SwitchTenant(ctx context.Context, in SwitchTenantInput) (*TokenPair, error) {
	member, err := s.q.CheckTenantMembership(ctx, dbgen.CheckTenantMembershipParams{
		UserID:   in.UserID,
		TenantID: in.TenantID,
	})
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, errs.ErrAuthNotTenantMember
	}
	// Cheap check before calling out to the hook; the supersede below is the
	// authoritative one.
	live, err := s.q.IsSessionLiveForUser(ctx, dbgen.IsSessionLiveForUserParams{SessionID: in.FromSessionID, UserID: in.UserID})
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errs.ErrUnauthorized
	}
	carried, err := s.carriedSecondFactor(ctx, in.FromSessionID, in.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.tenantFactorShortfall(ctx, in.UserID, in.TenantID, carried); err != nil {
		return nil, err
	}
	var claims map[string]any
	if s.loginHook != nil {
		u, err := s.users.Get(ctx, in.UserID)
		if err != nil {
			return nil, err
		}
		if claims, err = s.loginHook.Run(ctx, in.TenantID, in.UserID, u.Email); err != nil {
			return nil, err
		}
	}
	if err := s.refuseSignIn(ctx, in.UserID, in.TenantID, "tenant_switch", in.IP, in.UserAgent); err != nil {
		return nil, err
	}
	if err := s.refuseSwitchIntoCapture(ctx, in.UserID, in.TenantID); err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	// The user row first, in the order every bulk session revocation takes it.
	if _, err := q.LockUserForSessionRevocation(ctx, in.UserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized
		}
		return nil, err
	}
	// The same sign-in, so the new session ends when this one would have.
	ends, err := q.SessionEnd(ctx, dbgen.SessionEndParams{SessionID: in.FromSessionID, UserID: in.UserID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	pair, err := s.issuePairTx(ctx, tx, in.UserID, in.TenantID, in.IP, in.UserAgent, "tenant_switch", claims,
		map[string]any{"previous_session_id": in.FromSessionID, "second_factor": carried}, ends)
	if err != nil {
		return nil, s.signInFailed(ctx, tx, err)
	}
	if err := continueSession(ctx, tx, pair.SessionID, in.FromSessionID, carried); err != nil {
		return nil, err
	}
	left, err := q.SupersedeSession(ctx, dbgen.SupersedeSessionParams{
		NewSessionID: pgtype.UUID{Bytes: pair.SessionID, Valid: true},
		SessionID:    in.FromSessionID,
		UserID:       in.UserID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonTenantSwitch,
		endedSessions(in.UserID, []uuid.UUID{in.FromSessionID}, []pgtype.UUID{left})...)
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// SignInInvitedAccount signs in an account an accepted invitation has just
// created in tenantID, as at sign-up: where the organisation requires a second
// factor the result is the enrolment challenge instead of a session.
func (s *Service) SignInInvitedAccount(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*LoginResult, error) {
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	claims, err := s.signInHook(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if gate.challenged() {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, claims, gate, firstFactorPassword, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, userID, tenantID, ip, ua, "invite_accept", claims)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// EnterInvitedTenant issues a session in tenantID for an account that accepted
// its invitation while signed in. Like SwitchTenant, it is refused while the
// organisation's second-factor requirement isn't met; the invitation stays
// accepted so the user can step up and switch in.
func (s *Service) EnterInvitedTenant(ctx context.Context, userID, tenantID, fromSessionID uuid.UUID, ip, ua string) (*TokenPair, error) {
	return s.enterTenant(ctx, userID, tenantID, fromSessionID, ip, ua, "invite_accept")
}

// EnterCreatedTenant opens a session in tenantID, which userID has just
// created, continuing their session fromSessionID: it ends when that one
// would, and carries its sign-in and second factor.
func (s *Service) EnterCreatedTenant(ctx context.Context, userID, tenantID, fromSessionID uuid.UUID, ip, ua string) (*TokenPair, error) {
	return s.enterTenant(ctx, userID, tenantID, fromSessionID, ip, ua, "tenant_create")
}

// enterTenant opens a session in tenantID continuing userID's session
// fromSessionID (uuid.Nil: none), which stays open, recorded as a method
// sign-in.
func (s *Service) enterTenant(ctx context.Context, userID, tenantID, fromSessionID uuid.UUID, ip, ua, method string) (*TokenPair, error) {
	carried := ""
	if fromSessionID != uuid.Nil {
		var err error
		if carried, err = s.carriedSecondFactor(ctx, fromSessionID, userID); err != nil {
			return nil, err
		}
	}
	if err := s.tenantFactorShortfall(ctx, userID, tenantID, carried); err != nil {
		return nil, err
	}
	if err := s.refuseSignIn(ctx, userID, tenantID, method, ip, ua); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// The same sign-in, so the new session ends when this one would.
	var ends time.Time
	if fromSessionID != uuid.Nil {
		if ends, err = s.q.WithTx(tx).SessionEnd(ctx, dbgen.SessionEndParams{SessionID: fromSessionID, UserID: userID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errs.ErrUnauthorized
			}
			return nil, err
		}
	}
	pair, err := s.issuePairTx(ctx, tx, userID, tenantID, ip, ua, method, nil,
		map[string]any{"previous_session_id": fromSessionID, "second_factor": carried}, ends)
	if err != nil {
		return nil, s.signInFailed(ctx, tx, err)
	}
	if fromSessionID != uuid.Nil {
		if err := continueSession(ctx, tx, pair.SessionID, fromSessionID, carried); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// SessionFactorShortfall reports what stops userID acting in tenantID through
// their session sessionID (uuid.Nil: none, so no factor met), as entering it
// would: nil, or ErrStepUpRequired / ErrMFAEnrollmentRequired while tenantID
// requires a second factor the session's sign-in didn't meet.
func (s *Service) SessionFactorShortfall(ctx context.Context, sessionID, userID, tenantID uuid.UUID) error {
	carried := ""
	if sessionID != uuid.Nil {
		var err error
		if carried, err = s.carriedSecondFactor(ctx, sessionID, userID); err != nil {
			return err
		}
	}
	return s.tenantFactorShortfall(ctx, userID, tenantID, carried)
}

// carriedSecondFactor is the second factor a session's sign-in met, for a
// session opened from it to carry on: the sign-in's own, else "step_up" while
// the session holds a fresh step-up, else "". ErrUnauthorized when the session
// isn't the user's or has ended.
func (s *Service) carriedSecondFactor(ctx context.Context, sessionID, userID uuid.UUID) (string, error) {
	row, err := s.q.SessionSecondFactor(ctx, dbgen.SessionSecondFactorParams{SessionID: sessionID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	switch {
	case row.SecondFactor != "":
		return row.SecondFactor, nil
	case row.SteppedUp:
		return secondFactorStepUp, nil
	}
	return "", nil
}

// continueSession records on sessionID, opened from fromSessionID, that it
// continues that session's sign-in: when it happened, and the second factor
// carried from it ("": none).
func continueSession(ctx context.Context, tx pgx.Tx, sessionID, fromSessionID uuid.UUID, factor string) error {
	_, err := tx.Exec(ctx, `
		UPDATE auth.sessions s SET signed_in_at = f.signed_in_at, second_factor = COALESCE(NULLIF($3, ''), s.second_factor)
		FROM auth.sessions f
		WHERE s.id = $1 AND f.id = $2 AND f.user_id = s.user_id`, sessionID, fromSessionID, factor)
	return err
}
