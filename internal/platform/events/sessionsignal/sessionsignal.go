// Package sessionsignal announces ended API and console sessions
// (auth.sessions) to the organisations whose applications may hold the user's
// tokens, as the signed session.revoked webhook. Access tokens are verified
// offline, so this signal is how a subscribed application learns of a
// withdrawal before the token lapses.
//
// Every path that ends a session calls Signaller.Revoked inside the
// transaction that ends it, with one of the reasons below. The signals are
// queued in that transaction (ADR-0009) under a savepoint: when queueing
// fails, only the savepoint is rolled back — the revocation still commits —
// and the failure is counted in session_revocation_signal_failures_total.
//
// Destination: the session's organisation. A session with no organisation
// (the normal state after sign-up, and console sessions) is announced to
// every organisation the user belongs to — their home organisation and each
// one they hold a role in. A user who belongs to none has no subscriber to
// tell; nothing is queued.
//
// Payload: event_id (new for every signal: a redelivery of the same signal
// repeats it, and X-Qeet-Delivery-ID, while a new signal has a new one),
// user_id, session_id, tenant_id (null for a session with no organisation),
// reason and revoked_at. Deliveries are signed (X-Qeet-Signature) and
// retried by the webhook dispatcher.
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

// Reasons a session ends — the documented set a subscriber can rely on.
const (
	// ReasonLogout: the user signed the session out (or revoked it from
	// their session list).
	ReasonLogout = "logout"
	// ReasonReuseDetected: a refresh token was presented twice; the session
	// is ended as suspected theft.
	ReasonReuseDetected = "reuse_detected"
	// ReasonOtherSessionsRevoked: the user signed out their other sessions.
	ReasonOtherSessionsRevoked = "other_sessions_revoked"
	// ReasonAllSessionsRevoked: the user signed out everywhere.
	ReasonAllSessionsRevoked = "all_sessions_revoked"
	// ReasonAdminRevokedAll: an administrator force-signed the user out.
	ReasonAdminRevokedAll = "admin_revoked_all"
	// ReasonPasswordChanged: the user changed their password; their other
	// sessions end.
	ReasonPasswordChanged = "password_changed"
	// ReasonPasswordReset: a password reset was completed; every session ends.
	ReasonPasswordReset = "password_reset"
	// ReasonAdminPasswordSet: an administrator set the user's password; every
	// session ends.
	ReasonAdminPasswordSet = "admin_password_set"
	// ReasonTenantSwitch: the user switched organisation; the session they
	// switched from is superseded by a new one.
	ReasonTenantSwitch = "tenant_switch"
	// ReasonSuspended: the account was suspended.
	ReasonSuspended = "suspended"
	// ReasonDeprovisioned: the account was deactivated by SCIM provisioning.
	ReasonDeprovisioned = "deprovisioned"
	// ReasonReactivated: the account was reactivated; sessions from before
	// the suspension stay ended.
	ReasonReactivated = "reactivated"
	// ReasonDeleted: the account was deleted (soft-deleted by an
	// administrator, or erased).
	ReasonDeleted = "deleted"
	// ReasonExpired: every refresh token of the session expired without it
	// being ended; announced when the cleanup removes it.
	ReasonExpired = "expired"
	// ReasonSessionLimit: a new sign-in reached the organisation's limit on
	// simultaneous sessions, and this, the least recently used, was ended.
	ReasonSessionLimit = "session_limit"
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

// EndUserSessions ends every live session of userID inside tx and returns
// them, for Revoked. Used where an account change ends all of its sessions:
// password reset, an administrator setting the password, suspension,
// reactivation, deprovisioning and erasure. A session past its maximum age or
// idle timeout has already ended and is left as expired.
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
