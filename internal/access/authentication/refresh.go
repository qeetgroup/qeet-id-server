package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RefreshInput carries the rotation request plus client context used for
// auditing and theft-alert payloads. Callers that don't have IP/UA can
// leave them empty.
type RefreshInput struct {
	RefreshToken string
	// Actor is the request's client address, user agent and request ID, for
	// its audit record.
	audit.Actor
}

// Refresh rotates a refresh token and issues a new access token. Reusing an
// already-used token revokes the whole session as suspected theft and notifies
// the user, unless it is a retry within the reuse grace (refreshretry.go).
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (*TokenPair, error) {
	hash := tokens.HashRefresh(in.RefreshToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rt, err := s.q.WithTx(tx).LockRefreshToken(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, err
	}
	// uuid.Nil = organization-less session; preserved across refresh.
	var organizationID uuid.UUID
	if rt.OrganizationID != nil {
		organizationID = *rt.OrganizationID
	}
	if err := s.refuseEndedRefresh(ctx, tx, rt, organizationID, in); err != nil {
		return nil, err
	}
	if rt.UsedAt != nil {
		return s.answerReuse(ctx, tx, rt, organizationID, in)
	}

	// A session renews only from an address its organization still allows, so
	// a newly blocked address stops renewing. The session itself stays: it
	// renews again from an allowed address. Nothing else is written yet, so
	// committing keeps only the refusal's record.
	if err := s.checkAddressTx(ctx, tx, organizationID, rt.UserID, in.IP, "refresh"); err != nil {
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return nil, cerr
			}
		}
		return nil, err
	}
	pair, err := s.rotate(ctx, tx, rt, organizationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// refuseEndedRefresh refuses renewing rt when its session, account or organization has ended, or the
// token has expired. A session past its maximum age or idle timeout has ended whatever the client was
// told: the first renewal to notice records the ending (tx commits), and it is never renewed.
func (s *Service) refuseEndedRefresh(ctx context.Context, tx pgx.Tx, rt dbgen.LockRefreshTokenRow, organizationID uuid.UUID, in RefreshInput) error {
	if rt.PastMaxAge || rt.PastIdle {
		if rt.SessionRevokedAt == nil {
			reason := timedOutIdle
			if rt.PastMaxAge {
				reason = timedOutMaxAge
			}
			if err := s.endTimedOutSession(ctx, tx, rt.UserID, organizationID, rt.SessionID, reason, in); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
		}
		return ErrSessionTimedOut
	}
	if rt.SessionRevokedAt != nil {
		return errs.ErrAuthSessionRevoked
	}
	// Status changes and soft deletes don't end sessions, so without this check a
	// suspended or deleted user's refresh token would keep working.
	if rt.UserDeletedAt != nil || rt.UserStatus == "suspended" {
		return errs.ErrAuthAccountSuspended
	}
	// The same for the organization: suspending or deleting it ends its
	// sessions, and a refresh token that outlived that is refused.
	if !rt.OrganizationActive {
		return ErrOrganizationInactive
	}
	if time.Now().After(rt.ExpiresAt) {
		return ErrRefreshTokenInvalid
	}
	return nil
}

// answerReuse answers the used token rt sent again: a retry within the grace
// gets the pair its rotation issued; any other reuse means theft, so the
// session is revoked with its audit and outbox events, atomically (tx
// commits).
func (s *Service) answerReuse(ctx context.Context, tx pgx.Tx, rt dbgen.LockRefreshTokenRow, organizationID uuid.UUID, in RefreshInput) (*TokenPair, error) {
	pair, age, ok, err := s.keptRotation(ctx, tx, rt.ID, rt.SessionID)
	if err != nil {
		return nil, err
	}
	if ok {
		return s.answerRetry(ctx, tx, pair, age, rt.ID, rt.UserID, organizationID, in)
	}
	if err := s.handleRefreshReuse(ctx, tx, rt.UserID, organizationID, rt.SessionID, rt.ID, in); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return nil, errs.ErrAuthSessionRevoked
}

// rotate replaces rt with a new refresh token inside tx and returns the new
// pair: the renewal is the session's use, so its idle timeout counts from now;
// the hook claims taken when the session opened stay with it.
func (s *Service) rotate(ctx context.Context, tx pgx.Tx, rt dbgen.LockRefreshTokenRow, organizationID uuid.UUID) (*TokenPair, error) {
	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newID, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: rt.SessionID,
		TokenHash: newHash,
		ExpiresAt: s.refreshExpiry(rt.SessionExpiresAt),
	})
	if err != nil {
		return nil, err
	}
	if err := s.q.WithTx(tx).MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		ReplacedBy: &newID,
		ID:         rt.ID,
	}); err != nil {
		return nil, err
	}
	idleExp, err := s.q.WithTx(tx).UpdateSessionLastSeen(ctx, rt.SessionID)
	if err != nil {
		return nil, err
	}
	if err := user.RecordActive(ctx, tx, organizationID, rt.UserID); err != nil {
		return nil, err
	}
	var claims map[string]any
	if len(rt.HookClaims) > 0 {
		if err := json.Unmarshal(rt.HookClaims, &claims); err != nil {
			return nil, err
		}
	}
	access, exp, err := s.tokens.IssueSessionAccess(rt.UserID, organizationID, rt.SessionID, claims, rt.SessionExpiresAt)
	if err != nil {
		return nil, err
	}
	pair := &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     newRaw,
		SessionExpiresAt: rt.SessionExpiresAt,
		IdleExpiresAt:    idleExp,
		SessionID:        rt.SessionID,
		UserID:           rt.UserID,
		OrganizationID:   rt.OrganizationID,
	}
	if err := s.keepRotation(ctx, tx, rt.ID, pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// buildReuseEvents constructs the audit + outbox events emitted when a
// refresh-token reuse is detected. Exported as a free function so tests
// can verify the payload shape without a DB round-trip.
func buildReuseEvents(userID, organizationID, sessionID, refreshID uuid.UUID, in RefreshInput) (audit.Event, outbox.Event) {
	meta := map[string]any{
		"session_id":       sessionID,
		"refresh_token_id": refreshID,
		"reason":           "refresh_token_reuse",
	}
	if in.IP != "" {
		meta["ip"] = in.IP
	}
	if in.UserAgent != "" {
		meta["user_agent"] = in.UserAgent
	}

	// A session in no organization is recorded as the platform's, not under the
	// nil UUID.
	tid := orNil(organizationID)
	ae := as(in.Actor, "system", &userID).EventIn(tid, "auth.token_reuse_detected", "session", sessionID, meta)
	oe := outbox.Event{
		AggregateID: sessionID,
		Topic:       "auth",
		EventType:   "auth.session.revoked_for_reuse",
		Payload: map[string]any{
			"user_id":         userID,
			"organization_id": tid,
			"session_id":      sessionID,
			"ip":              in.IP,
			"user_agent":      in.UserAgent,
		},
	}
	return ae, oe
}

// handleRefreshReuse atomically records and revokes a stolen-token
// situation. Caller has already loaded the offending refresh row and is
// inside a transaction that will be committed only if every step here
// succeeds — leaving no half-state if e.g. the outbox insert fails.
func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx,
	userID, organizationID, sessionID, refreshID uuid.UUID, in RefreshInput,
) error {
	if err := s.q.WithTx(tx).RevokeSessionById(ctx, sessionID); err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonReuseDetected,
		sessionsignal.Session{ID: sessionID, UserID: userID, OrganizationID: organizationID})

	auditEvent, outboxEvent := buildReuseEvents(userID, organizationID, sessionID, refreshID, in)
	if err := audit.Record(ctx, tx, auditEvent); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outboxEvent); err != nil {
		return err
	}

	slog.Warn("refresh token reuse — session revoked",
		"user_id", userID,
		"organization_id", organizationID,
		"session_id", sessionID,
		"ip", in.IP,
	)
	return nil
}
