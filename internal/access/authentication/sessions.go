package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/useragent"
)

// otherSessionsEnded turns RevokeOtherSessionsForUser's rows into signals.
func otherSessionsEnded(userID uuid.UUID, rows []dbgen.RevokeOtherSessionsForUserRow) []sessionsignal.Session {
	ids, tenants := make([]uuid.UUID, len(rows)), make([]pgtype.UUID, len(rows))
	for i, r := range rows {
		ids[i], tenants[i] = r.ID, r.TenantID
	}
	return endedSessions(userID, ids, tenants)
}

// endedSessions turns the sessions a revocation query returned into signals.
func endedSessions(userID uuid.UUID, ids []uuid.UUID, tenants []pgtype.UUID) []sessionsignal.Session {
	out := make([]sessionsignal.Session, len(ids))
	for i, id := range ids {
		out[i] = sessionsignal.Session{ID: id, UserID: userID}
		if tenants[i].Valid {
			out[i].TenantID = uuid.UUID(tenants[i].Bytes)
		}
	}
	return out
}

// Logout revokes sessionID if it belongs to userID. It is idempotent: an
// already-revoked, unknown or other user's session is a no-op.
func (s *Service) Logout(ctx context.Context, sessionID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tenantID, err := s.q.WithTx(tx).RevokeSessionForUser(ctx, dbgen.RevokeSessionForUserParams{
		SessionID: sessionID,
		UserID:    userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonLogout,
		endedSessions(userID, []uuid.UUID{sessionID}, []pgtype.UUID{tenantID})...)
	return tx.Commit(ctx)
}

// RevokeOtherSessionsInput names the caller and the session they keep.
// CurrentSessionID must come from the caller's own access token, never from
// anything the client supplies.
type RevokeOtherSessionsInput struct {
	UserID           uuid.UUID
	CurrentSessionID uuid.UUID
	TenantID         *uuid.UUID
	IP               string
	UserAgent        string
	RequestID        string
}

// RevokeOtherSessions ends every live session of the user except the current one
// and returns how many it ended. It is all-or-nothing and locks the user row, so
// concurrent calls run in turn; a call from an already-ended session gets
// ErrAuthSessionRevoked.
func (s *Service) RevokeOtherSessions(ctx context.Context, in RevokeOtherSessionsInput) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if _, err := q.LockUserForSessionRevocation(ctx, in.UserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, errs.ErrUnauthorized
		}
		return 0, err
	}
	live, err := q.IsSessionLiveForUser(ctx, dbgen.IsSessionLiveForUserParams{
		SessionID: in.CurrentSessionID,
		UserID:    in.UserID,
	})
	if err != nil {
		return 0, err
	}
	if !live {
		return 0, errs.ErrAuthSessionRevoked
	}
	rows, err := q.RevokeOtherSessionsForUser(ctx, dbgen.RevokeOtherSessionsForUserParams{
		UserID:        in.UserID,
		KeepSessionID: in.CurrentSessionID,
	})
	if err != nil {
		return 0, err
	}
	revoked := int64(len(rows))
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonOtherSessionsRevoked, otherSessionsEnded(in.UserID, rows)...)
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.other_sessions_revoked", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{"revoked_sessions": revoked, "kept_session_id": in.CurrentSessionID},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

// SignInsEnded counts what signing someone out everywhere ended (see
// user.SignInsEnded).
type SignInsEnded = user.SignInsEnded

// RevokeAllSessionsInput names the caller. SessionID must come from the
// caller's own access token, never from anything the client supplies.
type RevokeAllSessionsInput struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	TenantID  *uuid.UUID
	IP        string
	UserAgent string
	RequestID string
}

// RevokeAllSessions signs the caller out everywhere: API and console sessions,
// hosted-login sessions and application grants. Issued access tokens stay valid
// until they expire. The token must name one of the caller's own sessions, and
// repeating the call is safe.
func (s *Service) RevokeAllSessions(ctx context.Context, in RevokeAllSessionsInput) (SignInsEnded, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SignInsEnded{}, err
	}
	defer tx.Rollback(ctx)
	owned, err := s.q.WithTx(tx).IsSessionOfUser(ctx, dbgen.IsSessionOfUserParams{
		SessionID: in.SessionID,
		UserID:    in.UserID,
	})
	if err != nil {
		return SignInsEnded{}, err
	}
	if !owned {
		return SignInsEnded{}, errs.ErrUnauthorized
	}
	var ended SignInsEnded
	ended, err = s.EndAllSignIns(ctx, tx, in.UserID, sessionsignal.ReasonAllSessionsRevoked)
	if err != nil {
		return SignInsEnded{}, err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.all_sessions_revoked", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
			"session_id":                   in.SessionID,
		},
	}); err != nil {
		return SignInsEnded{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SignInsEnded{}, err
	}
	return ended, nil
}

// maxGrantPasses bounds the passes EndAllSignIns makes over a user's
// application grants (see there).
const maxGrantPasses = 5

// EndAllSignIns ends, inside tx, the user's sessions, hosted-login sessions and
// application grants, and returns how many of each it ended. It locks the user
// row first and does not commit; reason is sent with the session.revoked
// signals. It returns errs.ErrNotFound for an unknown user.
func (s *Service) EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error) {
	return EndSignIns(ctx, tx, s.signals, userID, reason)
}

// EndSignIns is EndAllSignIns for a service that holds no *Service, such as
// password reset; signals (nil: none) announces the ended sessions.
func EndSignIns(ctx context.Context, tx pgx.Tx, signals *sessionsignal.Signaller, userID uuid.UUID, reason string) (SignInsEnded, error) {
	q := dbgen.New(tx)
	if _, err := q.LockUserForSessionRevocation(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SignInsEnded{}, errs.ErrNotFound
		}
		return SignInsEnded{}, err
	}
	rows, err := q.RevokeAllSessionsForUser(ctx, userID)
	if err != nil {
		return SignInsEnded{}, err
	}
	sessions := make([]sessionsignal.Session, len(rows))
	for i, r := range rows {
		sessions[i] = sessionsignal.Session{ID: r.ID, UserID: userID}
		if r.TenantID.Valid {
			sessions[i].TenantID = uuid.UUID(r.TenantID.Bytes)
		}
	}
	signals.Revoked(ctx, tx, reason, sessions...)
	ended, err := endOtherSignIns(ctx, tx, userID)
	if err != nil {
		return SignInsEnded{}, err
	}
	ended.Sessions = int64(len(rows))
	return ended, nil
}

// endOtherSignIns ends, inside tx, every way the user signs in besides their
// API sessions: hosted-login sessions, remembered devices, which skip the
// second factor, pending authorisations, which would become grants, and
// application grants. The caller has locked the user row.
func endOtherSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (SignInsEnded, error) {
	var ended SignInsEnded
	q := dbgen.New(tx)
	var err error
	if ended.LoginSessions, err = sessionsignal.EndLoginSessions(ctx, tx, userID); err != nil {
		return SignInsEnded{}, err
	}
	if ended.TrustedDevices, err = q.DeleteTrustedDevicesForUser(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	denyDevices := func(ctx context.Context, id uuid.UUID) (int64, error) {
		return q.DenyDeviceAuthorizationsForUser(ctx, pgtype.UUID{Bytes: id, Valid: true})
	}
	for _, deny := range []func(context.Context, uuid.UUID) (int64, error){
		q.SpendAuthorizationCodesForUser, denyDevices, q.DenyBackchannelRequestsForUser,
	} {
		n, err := deny(ctx, userID)
		if err != nil {
			return SignInsEnded{}, err
		}
		ended.PendingAuthorizations += n
	}
	// A grant renewed concurrently can commit after this pass's snapshot, so repeat
	// in new statements until a pass finds nothing; one extra pass is the norm.
	for pass := 0; pass < maxGrantPasses; pass++ {
		row, err := q.RevokeAppGrantsForUser(ctx, userID)
		if err != nil {
			return SignInsEnded{}, err
		}
		ended.AppGrants += row.Live
		if row.Touched == 0 {
			break
		}
	}
	return ended, nil
}

// SignInMethods counts the user's ways to sign in (see user.SignInMethods).
func (s *Service) SignInMethods(ctx context.Context, userID uuid.UUID) (user.SignInMethods, error) {
	return user.CountSignInMethods(ctx, s.pool, userID)
}

// Session is one of a person's API or console sessions, as listed to them.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	IP         *string    `json:"ip"`
	UserAgent  *string    `json:"user_agent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	// ExpiresAt is when the session ends however active it is, and
	// IdleExpiresAt when it ends unless renewed first. Status is "active",
	// "revoked" (ended by sign-out or revocation) or "expired" (reached its
	// maximum age or idle timeout first).
	ExpiresAt     time.Time `json:"expires_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	Status        string    `json:"status"`
	// Device describes the device and browser in words ("Chrome on macOS",
	// "Unknown device"), read from the user agent on the server so every
	// surface names it alike; DeviceKind is desktop, mobile, tablet or
	// unknown. The raw user agent stays in UserAgent, for support.
	Device     string `json:"device"`
	DeviceKind string `json:"device_kind"`
	// Country is where the session was opened, approximately (ISO 3166-1
	// alpha-2), when the deployment supplies it; omitted otherwise.
	Country string `json:"country,omitempty"`
	// Current marks the session the request listing them was made with.
	Current bool `json:"current"`
}

// ListSessions returns up to 100 of the user's live sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	page, err := s.ListSessionsPage(ctx, userID, 100, "")
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// SessionPage is one page of sessions and the cursor for the next.
type SessionPage struct {
	Items      []Session `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	HasMore    bool      `json:"has_more"`
	Total      int       `json:"total"`
}

// ListSessionsPage lists the user's sessions, newest first.
func (s *Service) ListSessionsPage(ctx context.Context, userID uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	return s.ListSessionsPageFor(ctx, userID, uuid.Nil, limit, cursor)
}

// ListSessionsPageFor is ListSessionsPage marking current (uuid.Nil: none) as
// the caller's own session.
func (s *Service) ListSessionsPageFor(ctx context.Context, userID, current uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	var cursorID uuid.UUID
	var cursorAt time.Time
	if cursor != "" {
		parsed, err := uuid.Parse(cursor)
		if err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		}
		cursorID = parsed
		if err := s.pool.QueryRow(ctx, `
			SELECT sess.created_at
			FROM auth.sessions sess
			JOIN "user".users u ON u.id = sess.user_id
			WHERE sess.id = $1 AND sess.user_id = $2 AND u.deleted_at IS NULL
		`, cursorID, userID).Scan(&cursorAt); errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		} else if err != nil {
			return nil, err
		}
	}
	// Soft-deleted users keep their session rows for audit purposes but
	// must not surface them via admin or self-service listings. Filter
	// at the join rather than relying on the caller to know about
	// `users.deleted_at`.
	rows, err := s.pool.Query(ctx, `
		SELECT sess.id, sess.user_id, sess.tenant_id, host(sess.ip), sess.user_agent,
		       sess.created_at, sess.last_seen_at, sess.revoked_at,
		       sess.expires_at, ends.idle,
		       CASE WHEN ends.idle <= COALESCE(sess.revoked_at, NOW()) THEN 'expired'
		            WHEN sess.revoked_at IS NOT NULL THEN 'revoked'
		            ELSE 'active' END,
		       COALESCE(sess.country, '')
		FROM auth.sessions sess
		CROSS JOIN LATERAL (SELECT LEAST(sess.last_seen_at + sess.idle_timeout, sess.expires_at) AS idle) ends
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL AND sess.superseded_by IS NULL
		  AND ($2::boolean = FALSE OR (sess.created_at, sess.id) < ($3, $4))
		ORDER BY sess.created_at DESC, sess.id DESC
		LIMIT $5
	`, userID, cursor != "", cursorAt, cursorID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Session, 0, limit+1)
	for rows.Next() {
		var session Session
		var tenantID pgtype.UUID
		if err := rows.Scan(&session.ID, &session.UserID, &tenantID, &session.IP, &session.UserAgent, &session.CreatedAt, &session.LastSeenAt, &session.RevokedAt,
			&session.ExpiresAt, &session.IdleExpiresAt, &session.Status, &session.Country); err != nil {
			return nil, err
		}
		ua := ""
		if session.UserAgent != nil {
			ua = *session.UserAgent
		}
		device := useragent.Parse(ua)
		session.Device, session.DeviceKind = device.Label(), device.Kind
		session.Current = current != uuid.Nil && session.ID == current
		if tenantID.Valid {
			session.TenantID = uuid.UUID(tenantID.Bytes)
		}
		out = append(out, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	nextCursor := ""
	if hasMore && len(out) > 0 {
		nextCursor = out[len(out)-1].ID.String()
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM auth.sessions sess
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL AND sess.superseded_by IS NULL
	`, userID).Scan(&total); err != nil {
		return nil, err
	}
	return &SessionPage{Items: out, NextCursor: nextCursor, HasMore: hasMore, Total: total}, nil
}
