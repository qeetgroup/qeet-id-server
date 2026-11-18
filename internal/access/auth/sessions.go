package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// otherSessionsEnded turns RevokeOtherSessionsForUser's rows into signals.
func otherSessionsEnded(userID uuid.UUID, rows []dbgen.RevokeOtherSessionsForUserRow) []sessionsignal.Session {
	ids, organizations := make([]uuid.UUID, len(rows)), make([]*uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i], organizations[i] = r.ID, r.OrganizationID
	}
	return endedSessions(userID, ids, organizations)
}

// endedSessions turns the sessions a revocation query returned into signals.
func endedSessions(userID uuid.UUID, ids []uuid.UUID, organizations []*uuid.UUID) []sessionsignal.Session {
	out := make([]sessionsignal.Session, len(ids))
	for i, id := range ids {
		out[i] = sessionsignal.Session{ID: id, UserID: userID}
		if organizations[i] != nil {
			out[i].OrganizationID = postgres.ZeroIfNull(organizations[i])
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
	organizationID, err := s.q.WithTx(tx).RevokeSessionForUser(ctx, dbgen.RevokeSessionForUserParams{
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
		endedSessions(userID, []uuid.UUID{sessionID}, []*uuid.UUID{organizationID})...)
	return tx.Commit(ctx)
}

// RevokeOtherSessionsInput names the caller and the session they keep.
// CurrentSessionID must come from the caller's own access token, never from
// anything the client supplies.
type RevokeOtherSessionsInput struct {
	UserID           uuid.UUID
	CurrentSessionID uuid.UUID
	OrganizationID   *uuid.UUID
	// Actor is the request's client address, user agent and request ID, for
	// its audit record.
	audit.Actor
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
	if err := audit.Record(ctx, tx, as(in.Actor, "user", &in.UserID).EventIn(in.OrganizationID, "auth.other_sessions_revoked", "user", in.UserID,
		map[string]any{"revoked_sessions": revoked, "kept_session_id": in.CurrentSessionID})); err != nil {
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
	UserID         uuid.UUID
	SessionID      uuid.UUID
	OrganizationID *uuid.UUID
	// Actor is the request's client address, user agent and request ID, for
	// its audit record.
	audit.Actor
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
	if err := audit.Record(ctx, tx, as(in.Actor, "user", &in.UserID).EventIn(in.OrganizationID, "auth.all_sessions_revoked", "user", in.UserID,
		map[string]any{
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
			"session_id":                   in.SessionID,
		})); err != nil {
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
		if r.OrganizationID != nil {
			sessions[i].OrganizationID = *r.OrganizationID
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
// API sessions: hosted-login sessions, unused password-reset and sign-in
// links, remembered devices, which skip the second factor, pending
// authorisations, which would become grants, and application grants. It also
// lifts a lock of their second-factor sign-in: the person proved who they are
// another way. The caller has locked the user row.
func endOtherSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (SignInsEnded, error) {
	var ended SignInsEnded
	q := dbgen.New(tx)
	var err error
	if ended.LoginSessions, err = sessionsignal.EndLoginSessions(ctx, tx, userID); err != nil {
		return SignInsEnded{}, err
	}
	if err := q.ExpireRecoveryLinksForUser(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	if err := q.EndMFAFailureStreak(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	if ended.TrustedDevices, err = q.DeleteTrustedDevicesForUser(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	denyDevices := func(ctx context.Context, id uuid.UUID) (int64, error) {
		return q.DenyDeviceAuthorizationsForUser(ctx, &id)
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

// ExpireRecoveryLinks ends, inside tx, userID's unused password-reset links
// and the unused sign-in links to their address, as a change of address does.
func ExpireRecoveryLinks(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	return dbgen.New(tx).ExpireRecoveryLinksForUser(ctx, userID)
}

// SignInMethods counts the user's ways to sign in (see user.SignInMethods).
func (s *Service) SignInMethods(ctx context.Context, userID uuid.UUID) (user.SignInMethods, error) {
	return user.CountSignInMethods(ctx, s.pool, userID)
}

// Session is one of a person's API or console sessions, as listed to them.
type Session struct {
	ID             uuid.UUID  `json:"id"`
	UserID         uuid.UUID  `json:"user_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	IP             *string    `json:"ip"`
	UserAgent      *string    `json:"user_agent"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
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
	// City is the city it was opened from, approximately, when the deployment
	// supplies it; omitted otherwise.
	City string `json:"city,omitempty"`
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

// SessionPage is one page of sessions and the cursor for the next, the last
// session's ID. HasMore reports there is a next page; Total counts them all.
type SessionPage struct {
	paging.Result[Session]
	HasMore bool `json:"has_more"`
	Total   int  `json:"total"`
}

// ListSessionsPage lists the user's sessions, newest first.
func (s *Service) ListSessionsPage(ctx context.Context, userID uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	return s.ListSessionsPageFor(ctx, userID, uuid.Nil, limit, cursor)
}

// ListSessionsPageFor is ListSessionsPage marking current (uuid.Nil: none) as
// the caller's own session. limit is 50 when unset, at most 100.
func (s *Service) ListSessionsPageFor(ctx context.Context, userID, current uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	limit = paging.Clamp(limit, 50, 100)
	params := dbgen.ListUserSessionsParams{UserID: userID, Lim: int32(limit + 1)} // #nosec G115 -- at most 101
	if cursor != "" {
		parsed, err := uuid.Parse(cursor)
		if err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		}
		at, err := s.q.SessionCursorTime(ctx, dbgen.SessionCursorTimeParams{ID: parsed, UserID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		} else if err != nil {
			return nil, err
		}
		params.After, params.BeforeTs, params.BeforeID = true, at, parsed
	}
	rows, err := s.q.ListUserSessions(ctx, params)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(rows))
	for _, row := range rows {
		session := Session{
			ID: row.ID, UserID: row.UserID, OrganizationID: postgres.ZeroIfNull(row.OrganizationID), IP: postgres.NullIfZero(row.Ip),
			UserAgent: row.UserAgent, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt, RevokedAt: row.RevokedAt,
			ExpiresAt: row.ExpiresAt, IdleExpiresAt: row.IdleExpiresAt, Status: row.Status, Country: row.Country, City: row.City,
			Current: current != uuid.Nil && row.ID == current,
		}
		device := httpx.Parse(postgres.ZeroIfNull(row.UserAgent))
		session.Device, session.DeviceKind = device.Label(), device.Kind
		out = append(out, session)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	nextCursor := ""
	if hasMore && len(out) > 0 {
		nextCursor = out[len(out)-1].ID.String()
	}
	total, err := s.q.CountUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &SessionPage{Result: paging.Page(out, nextCursor), HasMore: hasMore, Total: int(total)}, nil
}
