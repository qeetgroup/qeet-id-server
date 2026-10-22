// Package sessionsignal sends the session.revoked webhook when an API or
// console session ends, so applications that verify access tokens offline learn
// of the revocation before the token expires. Signals are queued in the
// transaction that ends the session, and a failure to queue never blocks it.
package sessionsignal

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EventType is the webhook event a session revocation is announced as.
const EventType = "session.revoked"

// Reasons a session ends, sent as the reason field of session.revoked.
const (
	ReasonLogout                  = "logout"                    // the user signed the session out
	ReasonReuseDetected           = "reuse_detected"            // a refresh token was used twice
	ReasonOtherSessionsRevoked    = "other_sessions_revoked"    // the user signed out their other sessions
	ReasonAllSessionsRevoked      = "all_sessions_revoked"      // the user signed out everywhere
	ReasonAdminRevokedAll         = "admin_revoked_all"         // an administrator signed the user out
	ReasonPasswordChanged         = "password_changed"          // other sessions end; the current one stays
	ReasonPasswordReset           = "password_reset"            // every session ends
	ReasonAdminPasswordSet        = "admin_password_set"        // an administrator set the password
	ReasonTenantSwitch            = "tenant_switch"             // replaced by a session in another organisation
	ReasonSuspended               = "suspended"                 // the account was suspended
	ReasonDeprovisioned           = "deprovisioned"             // SCIM deactivated the account
	ReasonReactivated             = "reactivated"               // sessions from before the suspension stay ended
	ReasonDeleted                 = "deleted"                   // the account was deleted
	ReasonRemovedFromOrganization = "removed_from_organization" // the user was removed from the organisation
	ReasonTenantSuspended         = "tenant_suspended"          // the session's organisation was suspended
	ReasonTenantDeleted           = "tenant_deleted"            // the session's organisation was deleted
	ReasonExpired                 = "expired"                   // all refresh tokens expired; sent at cleanup
	ReasonSessionLimit            = "session_limit"             // ended to stay within the session limit
)

// Session is one ended session. TenantID is uuid.Nil for a session with no
// organisation.
type Session struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	TenantID uuid.UUID
}

// Enqueuer queues a webhook event for tenantID's subscribers inside tx.
// Satisfied by the webhook service's EnqueueTx.
type Enqueuer func(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, eventType string, payload any) error

// Signaller announces ended sessions. A nil *Signaller announces nothing.
type Signaller struct {
	enqueue Enqueuer
}

// New returns a Signaller that queues through enqueue.
func New(enqueue Enqueuer) *Signaller { return &Signaller{enqueue: enqueue} }

var failures = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "session_revocation_signal_failures_total",
	Help: "Session revocations whose session.revoked signals could not be queued (the revocation still held), by reason.",
}, []string{"reason"})

// Revoked queues a session.revoked signal for each session, inside tx. It
// never fails the revocation: on any error the signals are rolled back to a
// savepoint, the failure is counted and logged, and the caller carries on.
func (s *Signaller) Revoked(ctx context.Context, tx pgx.Tx, reason string, sessions ...Session) {
	if s == nil || s.enqueue == nil || len(sessions) == 0 {
		return
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT session_revocation_signals"); err != nil {
		s.failed(reason, len(sessions), err)
		return
	}
	if err := s.queue(ctx, tx, reason, sessions); err != nil {
		if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT session_revocation_signals"); rerr != nil {
			slog.Error("session revocation signals: rollback to savepoint", "err", rerr)
		}
		s.failed(reason, len(sessions), err)
		return
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT session_revocation_signals"); err != nil {
		s.failed(reason, len(sessions), err)
	}
}

// queue sends each session's signal to its organisation, or to every
// organisation the user belongs to when the session has none.
func (s *Signaller) queue(ctx context.Context, tx pgx.Tx, reason string, sessions []Session) error {
	now := time.Now().UTC()
	for _, sess := range sessions {
		destinations := []uuid.UUID{sess.TenantID}
		var tenant any = sess.TenantID
		if sess.TenantID == uuid.Nil {
			tenant = nil
			ds, err := organisationsOf(ctx, tx, sess.UserID)
			if err != nil {
				return err
			}
			destinations = ds
		}
		payload := map[string]any{
			"event_id":   uuid.New(),
			"user_id":    sess.UserID,
			"session_id": sess.ID,
			"tenant_id":  tenant,
			"reason":     reason,
			"revoked_at": now,
		}
		for _, tid := range destinations {
			if err := s.enqueue(ctx, tx, tid, EventType, payload); err != nil {
				return err
			}
		}
	}
	return nil
}

// EndUserSessions ends every live session of userID inside tx and returns them
// for Revoked. Sessions past their maximum age or idle timeout are left as expired.
func EndUserSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]Session, error) {
	rows, err := tx.Query(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
		  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
		RETURNING id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Session, error) {
		sess := Session{UserID: userID}
		err := row.Scan(&sess.ID, &sess.TenantID)
		return sess, err
	})
}

// EndUserSessionsInTenant ends userID's live sessions in tenantID only and
// returns them for Revoked.
func EndUserSessionsInTenant(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID) ([]Session, error) {
	rows, err := tx.Query(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
		  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
		RETURNING id`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Session, error) {
		sess := Session{UserID: userID, TenantID: tenantID}
		err := row.Scan(&sess.ID)
		return sess, err
	})
}

// EndLoginSessions deletes every hosted sign-in (browser) session of userID
// inside tx and returns how many had not yet expired. Password changes call it
// so a browser session opened with the old password cannot outlive it.
func EndLoginSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int64, error) {
	var live int64
	err := tx.QueryRow(ctx, `
		WITH ended AS (
			DELETE FROM auth.login_sessions WHERE user_id = $1
			RETURNING expires_at
		)
		SELECT COUNT(*) FILTER (WHERE expires_at > NOW()) FROM ended`, userID).Scan(&live)
	return live, err
}

// EndTenantSessions ends every live session in tenantID and returns them for Revoked.
func EndTenantSessions(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) ([]Session, error) {
	rows, err := tx.Query(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW()
		WHERE tenant_id = $1 AND revoked_at IS NULL
		  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
		RETURNING id, user_id`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Session, error) {
		sess := Session{TenantID: tenantID}
		err := row.Scan(&sess.ID, &sess.UserID)
		return sess, err
	})
}

// organisationsOf is every organisation userID belongs to: their home
// organisation and each one they hold a role in.
func organisationsOf(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT tenant_id FROM "user".users WHERE id = $1 AND tenant_id IS NOT NULL
		UNION
		SELECT tenant_id FROM rbac.user_roles WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (s *Signaller) failed(reason string, n int, err error) {
	failures.WithLabelValues(reason).Inc()
	slog.Error("session revocation signals could not be queued; the revocation stands",
		"reason", reason, "sessions", n, "err", err)
}
