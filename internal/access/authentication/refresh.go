package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
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
	IP           string
	UserAgent    string
	RequestID    string
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

	var (
		id          uuid.UUID
		sessionID   uuid.UUID
		usedAt      *time.Time
		expiresAt   time.Time
		sessionRev  *time.Time
		userID      uuid.UUID
		tenantPtr   *uuid.UUID
		userStatus  string
		userDeleted *time.Time
		hookClaims  []byte
		sessionExp  time.Time
		pastMaxAge  bool
		pastIdle    bool
		// tenantActive: the session's organisation is neither suspended nor
		// deleted (true for a tenant-less session).
		tenantActive bool
	)
	// Whether the session had reached its maximum age or idle timeout by the
	// time it ended — now, if it has not ended — is decided on the database's
	// clock, as the bounds were set.
	row := tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
		       s.revoked_at, s.user_id, s.tenant_id, u.status, u.deleted_at, s.hook_claims,
		       s.expires_at,
		       s.expires_at <= COALESCE(s.revoked_at, NOW()),
		       s.last_seen_at + s.idle_timeout <= COALESCE(s.revoked_at, NOW()),
		       s.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL)
		FROM auth.refresh_tokens rt
		JOIN auth.sessions s ON s.id = rt.session_id
		JOIN "user".users u ON u.id = s.user_id
		LEFT JOIN tenant.tenants t ON t.id = s.tenant_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt, s
	`, hash)
	if err := row.Scan(&id, &sessionID, &usedAt, &expiresAt, &sessionRev, &userID, &tenantPtr, &userStatus, &userDeleted, &hookClaims,
		&sessionExp, &pastMaxAge, &pastIdle, &tenantActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrAuthRefreshTokenInvalid
		}
		return nil, err
	}
	// uuid.Nil = tenant-less session; preserved across refresh.
	var tenantID uuid.UUID
	if tenantPtr != nil {
		tenantID = *tenantPtr
	}
	// A session past its maximum age or idle timeout has ended, whatever the
	// client was told and whether or not it is the first renewal to notice.
	// The first one records the ending; it is never renewed.
	if pastMaxAge || pastIdle {
		if sessionRev == nil {
			reason := timedOutIdle
			if pastMaxAge {
				reason = timedOutMaxAge
			}
			if err := s.endTimedOutSession(ctx, tx, userID, tenantID, sessionID, reason, in); err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
		}
		return nil, errs.ErrAuthSessionTimedOut
	}
	if sessionRev != nil {
		return nil, errs.ErrAuthSessionRevoked
	}
	// Status changes and soft deletes don't end sessions, so without this check a
	// suspended or deleted user's refresh token would keep working.
	if userDeleted != nil || userStatus == "suspended" {
		return nil, errs.ErrAuthAccountSuspended
	}
	// The same for the organisation: suspending or deleting it ends its
	// sessions, and a refresh token that outlived that is refused.
	if !tenantActive {
		return nil, errs.ErrAuthTenantInactive
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrAuthRefreshTokenInvalid
	}
	if usedAt != nil {
		// A retry within the grace gets the pair its rotation issued.
		pair, age, ok, err := s.keptRotation(ctx, tx, id, sessionID)
		if err != nil {
			return nil, err
		}
		if ok {
			return s.answerRetry(ctx, tx, pair, age, id, userID, tenantID, in)
		}
		// Any other reuse means theft: revoke the session and record the audit
		// and outbox events atomically with the revocation.
		if err := s.handleRefreshReuse(ctx, tx, userID, tenantID, sessionID, id, in); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrAuthSessionRevoked
	}

	// A session renews only from an address its organisation still allows, so
	// a newly blocked address stops renewing. The session itself stays: it
	// renews again from an allowed address. Nothing else is written yet, so
	// committing keeps only the refusal's record.
	if err := s.checkAddressTx(ctx, tx, tenantID, userID, in.IP, "refresh"); err != nil {
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return nil, cerr
			}
		}
		return nil, err
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newID, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: newHash,
		ExpiresAt: s.refreshExpiry(sessionExp),
	})
	if err != nil {
		return nil, err
	}
	if err := s.q.WithTx(tx).MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		ReplacedBy: pgtype.UUID{Bytes: newID, Valid: true},
		ID:         id,
	}); err != nil {
		return nil, err
	}
	// The renewal is the session's use: its idle timeout counts from now.
	idleExp, err := s.q.WithTx(tx).UpdateSessionLastSeen(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	// The hook ran when the session was opened; its claims stay with the session.
	var claims map[string]any
	if len(hookClaims) > 0 {
		if err := json.Unmarshal(hookClaims, &claims); err != nil {
			return nil, err
		}
	}
	access, exp, err := s.tokens.IssueSessionAccess(userID, tenantID, sessionID, claims, sessionExp)
	if err != nil {
		return nil, err
	}
	pair := &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     newRaw,
		SessionExpiresAt: sessionExp,
		IdleExpiresAt:    idleExp,
		SessionID:        sessionID,
		UserID:           userID,
		TenantID:         tenantPtr,
	}
	if err := s.keepRotation(ctx, tx, id, pair); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// buildReuseEvents constructs the audit + outbox events emitted when a
// refresh-token reuse is detected. Exported as a free function so tests
// can verify the payload shape without a DB round-trip.
func buildReuseEvents(userID, tenantID, sessionID, refreshID uuid.UUID, in RefreshInput) (audit.Event, outbox.Event) {
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

	// A session in no organisation is recorded as the platform's, not under the
	// nil UUID.
	var tid *uuid.UUID
	if tenantID != uuid.Nil {
		tid = &tenantID
	}
	uid := userID
	sid := sessionID
	ae := audit.Event{
		TenantID:     tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "auth.token_reuse_detected",
		ResourceType: "session",
		ResourceID:   &sid,
		IP:           in.IP,
		UserAgent:    in.UserAgent,
		RequestID:    in.RequestID,
		Metadata:     meta,
	}
	oe := outbox.Event{
		AggregateID: sessionID,
		Topic:       "auth",
		EventType:   "auth.session.revoked_for_reuse",
		Payload: map[string]any{
			"user_id":    userID,
			"tenant_id":  tid,
			"session_id": sessionID,
			"ip":         in.IP,
			"user_agent": in.UserAgent,
		},
	}
	return ae, oe
}

// handleRefreshReuse atomically records and revokes a stolen-token
// situation. Caller has already loaded the offending refresh row and is
// inside a transaction that will be committed only if every step here
// succeeds — leaving no half-state if e.g. the outbox insert fails.
func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx,
	userID, tenantID, sessionID, refreshID uuid.UUID, in RefreshInput,
) error {
	if err := s.q.WithTx(tx).RevokeSessionById(ctx, sessionID); err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonReuseDetected,
		sessionsignal.Session{ID: sessionID, UserID: userID, TenantID: tenantID})

	auditEvent, outboxEvent := buildReuseEvents(userID, tenantID, sessionID, refreshID, in)
	if err := audit.Record(ctx, tx, auditEvent); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outboxEvent); err != nil {
		return err
	}

	slog.Warn("refresh token reuse — session revoked",
		"user_id", userID,
		"tenant_id", tenantID,
		"session_id", sessionID,
		"ip", in.IP,
	)
	return nil
}
