package auth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An organisation may cap the live sessions one person holds in it
// (max_sessions). At the cap a new sign-in either ends the least recently used
// session (evict_oldest, the default) or is refused. The check runs under the
// account's lock, so concurrent sign-ins can't both pass.

const (
	sessionLimitEvict  = "evict_oldest"
	sessionLimitRefuse = "refuse"
)

func (s *Service) enforceSessionLimit(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID, ip, ua string) error {
	var max *int32
	var action string
	err := tx.QueryRow(ctx, `
		SELECT max_sessions, session_limit_action FROM tenant.security_policies WHERE tenant_id = $1`,
		tenantID).Scan(&max, &action)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && max == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := s.q.WithTx(tx).LockUserForSessionRevocation(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrUnauthorized
		}
		return err
	}
	rows, err := tx.Query(ctx, `
		SELECT id FROM auth.sessions
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
		  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
		ORDER BY last_seen_at, created_at`, userID, tenantID)
	if err != nil {
		return err
	}
	live, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	over := len(live) - int(*max) + 1
	if over <= 0 {
		return nil
	}
	tid := tenantID
	if action == sessionLimitRefuse {
		// Recorded on its own: the sign-in it describes is rolled back.
		if err := s.recordOnItsOwn(ctx, audit.Event{
			TenantID: &tid, ActorUserID: &userID, ActorType: "user",
			Action: "auth.sign_in_refused_session_limit", ResourceType: "user", ResourceID: &userID,
			IP: ip, UserAgent: ua,
			Metadata: map[string]any{"max_sessions": *max, "live_sessions": len(live)},
		}); err != nil {
			return err
		}
		return errs.ErrAuthSessionLimit
	}
	evicted := live[:over]
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = ANY($1) AND revoked_at IS NULL`, evicted); err != nil {
		return err
	}
	ended := make([]sessionsignal.Session, len(evicted))
	for i, id := range evicted {
		ended[i] = sessionsignal.Session{ID: id, UserID: userID, TenantID: tenantID}
		sid := id
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID: &tid, ActorUserID: &userID, ActorType: "system",
			Action: "auth.session_evicted", ResourceType: "session", ResourceID: &sid,
			IP: ip, UserAgent: ua,
			Metadata: map[string]any{"reason": "session_limit", "max_sessions": *max},
		}); err != nil {
			return err
		}
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonSessionLimit, ended...)
	return nil
}

func (s *Service) recordOnItsOwn(ctx context.Context, e audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
