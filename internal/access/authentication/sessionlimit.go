package authentication

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An organization may cap the live sessions one person holds in it
// (max_sessions). At the cap a new sign-in either ends the least recently used
// session (evict_oldest, the default) or is refused. The check runs under the
// account's lock, so concurrent sign-ins can't both pass.

const (
	sessionLimitEvict  = "evict_oldest"
	sessionLimitRefuse = "refuse"
)

func (s *Service) enforceSessionLimit(ctx context.Context, tx pgx.Tx, userID, organizationID uuid.UUID, ip, ua string) error {
	q := s.q.WithTx(tx)
	limit, err := q.SessionLimit(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && limit.MaxSessions == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	max, action := limit.MaxSessions, limit.SessionLimitAction
	if _, err := q.LockUserForSessionRevocation(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrUnauthorized
		}
		return err
	}
	live, err := q.LiveSessionsByUse(ctx, dbgen.LiveSessionsByUseParams{UserID: userID, OrganizationID: &organizationID})
	if err != nil {
		return err
	}
	over := len(live) - int(*max) + 1
	if over <= 0 {
		return nil
	}
	by := asUser(userID, ip, ua)
	if action == sessionLimitRefuse {
		// Recorded by signInFailed once the sign-in it describes is rolled back.
		return &sessionLimitRefusal{event: by.Event(organizationID, "auth.sign_in_refused_session_limit", "user", userID,
			map[string]any{"max_sessions": *max, "live_sessions": len(live)})}
	}
	evicted := live[:over]
	if err := q.EvictSessions(ctx, evicted); err != nil {
		return err
	}
	// The system ends them, on the signing-in person's behalf.
	by.Type = "system"
	ended := make([]sessionsignal.Session, len(evicted))
	for i, id := range evicted {
		ended[i] = sessionsignal.Session{ID: id, UserID: userID, OrganizationID: organizationID}
		if err := audit.Record(ctx, tx, by.Event(organizationID, "auth.session_evicted", "session", id,
			map[string]any{"reason": "session_limit", "max_sessions": *max})); err != nil {
			return err
		}
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonSessionLimit, ended...)
	return nil
}

// sessionLimitRefusal is ErrAuthSessionLimit carrying the refusal's audit
// record, which must outlive the sign-in's rolled-back transaction.
type sessionLimitRefusal struct{ event audit.Event }

func (*sessionLimitRefusal) Error() string { return ErrSessionLimit.Error() }

func (*sessionLimitRefusal) Unwrap() error { return ErrSessionLimit }

// signInFailed is what a caller of issuePairTx returns for its error err. A
// session-limit refusal rolls tx back first, then records the refusal on its
// own and is ErrAuthSessionLimit; any other err is returned as it is.
func (s *Service) signInFailed(ctx context.Context, tx pgx.Tx, err error) error {
	var refusal *sessionLimitRefusal
	if !errors.As(err, &refusal) {
		return err
	}
	_ = tx.Rollback(ctx)
	if err := audit.RecordAlone(ctx, s.pool, refusal.event); err != nil {
		return err
	}
	return ErrSessionLimit
}

// A session's last use: last_seen_at moves on every renewal and, through
// SessionUsed, on requests made with its access tokens — at most once a
// minute per session — so its idle timeout counts from its last use and the
// session list shows when it was really last active.

// sessionUseInterval is how often a session's use is written at most.
const sessionUseInterval = time.Minute

type sessionUses struct {
	mu   sync.Mutex
	seen map[uuid.UUID]time.Time
}

// SessionUsed records that a request was made with sessionID's access token.
// Best effort: a failure is logged, never fails the request. Wired as
// httpx.AuthVerifier.SessionUsed in internal/bootstrap.
func (s *Service) SessionUsed(ctx context.Context, sessionID uuid.UUID) {
	now := time.Now()
	s.uses.mu.Lock()
	if s.uses.seen == nil || len(s.uses.seen) > 100_000 {
		s.uses.seen = make(map[uuid.UUID]time.Time)
	}
	due := now.Sub(s.uses.seen[sessionID]) >= sessionUseInterval
	if due {
		s.uses.seen[sessionID] = now
	}
	s.uses.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.q.TouchSession(ctx, sessionID); err != nil {
		slog.Warn("session use not recorded", "session_id", sessionID, "err", err)
	}
}

// SessionLive reports whether sessionID is one of userID's sessions that has
// not ended: not revoked, expired or idle past its timeout. Wired as
// httpx.AuthVerifier.SessionLive, so an ended session's access tokens stop
// working at once.
func (s *Service) SessionLive(ctx context.Context, sessionID, userID uuid.UUID) (bool, error) {
	return s.q.IsSessionLiveForUser(ctx, dbgen.IsSessionLiveForUserParams{SessionID: sessionID, UserID: userID})
}
