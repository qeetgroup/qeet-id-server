// Package auth handles login, refresh, logout, and session storage.
// Access & ID tokens are signed with ES256 (asymmetric) and verifiable via the
// public JWKS; see internal/platform/tokens.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/outbox"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
	"github.com/qeetgroup/qeet-identity/internal/platform/pgxerr"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
	"github.com/qeetgroup/qeet-identity/internal/user"
)

type Service struct {
	pool   *pgxpool.Pool
	users  *user.Repository
	tokens *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, users *user.Repository, t *tokens.Issuer) *Service {
	return &Service{pool: pool, users: users, tokens: t}
}

type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

type SignupInput struct {
	Email       string
	Password    string
	DisplayName string
	IP          string
	UserAgent   string
}

// RefreshInput carries the rotation request plus client context used for
// auditing and theft-alert payloads. Callers that don't have IP/UA can
// leave them empty.
type RefreshInput struct {
	RefreshToken string
	IP           string
	UserAgent    string
	RequestID    string
}

// TenantBrief is the small tenant projection returned alongside Signup.
type TenantBrief struct {
	ID     uuid.UUID `json:"id"`
	Slug   string    `json:"slug"`
	Name   string    `json:"name"`
	Plan   string    `json:"plan"`
	Region string    `json:"region"`
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	SessionID    uuid.UUID `json:"session_id"`
	UserID       uuid.UUID `json:"user_id"`
	// Tenant the token is scoped to; nil/omitted for a tenant-less session.
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
}

// Signup creates a tenant-less identity (user + password + session) and logs them in; no tenant or role is created.
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback(ctx)

	// 1) User — tenant-less (tenant_id NULL).
	var displayName any
	if in.DisplayName != "" {
		displayName = in.DisplayName
	}
	u := &user.User{Email: strings.TrimSpace(in.Email), Status: "active", Metadata: map[string]any{}}
	if in.DisplayName != "" {
		dn := in.DisplayName
		u.DisplayName = &dn
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name)
		VALUES (NULL, $1, $2)
		RETURNING id, created_at, updated_at
	`, u.Email, displayName).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if pgxerr.IsUnique(err) {
			return nil, nil, nil, errs.ErrConflict.WithDetail("email already exists")
		}
		return nil, nil, nil, err
	}

	// 2) Password credential.
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash)
		VALUES ($1, $2)
	`, u.ID, hash); err != nil {
		return nil, nil, nil, err
	}

	// 3) Tenant-less session + access + refresh token, all in the same tx so
	// signup is fully atomic.
	sessionID := uuid.New()
	var ipArg any
	if in.IP != "" {
		ipArg = in.IP
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
		VALUES ($1, $2, NULL, NULLIF($3,'')::inet, $4)
	`, sessionID, u.ID, ipArg, in.UserAgent); err != nil {
		return nil, nil, nil, err
	}
	access, exp, err := s.tokens.IssueAccess(u.ID, uuid.Nil, sessionID, "")
	if err != nil {
		return nil, nil, nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, nil, nil, err
	}
	refreshExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (session_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, sessionID, refreshHash, refreshExp); err != nil {
		return nil, nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: refreshRaw,
		SessionID:    sessionID,
		UserID:       u.ID,
	}, u, nil, nil
}

// SwitchTenant mints a token pair scoped to tenantID if the user is a member; ErrForbidden otherwise.
func (s *Service) SwitchTenant(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*TokenPair, error) {
	var member bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2
		)
	`, userID, tenantID).Scan(&member); err != nil {
		return nil, err
	}
	if !member {
		return nil, errs.ErrForbidden.WithDetail("not a member of this tenant")
	}
	return s.IssuePair(ctx, userID, tenantID, ip, ua, "tenant_switch")
}

func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	u, err := s.CheckPassword(ctx, in.Email, in.Password)
	if err != nil {
		return nil, err
	}
	return s.IssuePair(ctx, u.ID, u.TenantID, in.IP, in.UserAgent, "password")
}

// CheckPassword runs the full credential check — brute-force lockout, user
// lookup, password verify, transparent Argon2id rehash-on-login, and
// clear-on-success — returning the authenticated user. Shared by API login
// (which then issues tokens) and the hosted-login SSO session (which sets a
// cookie). It deliberately does not mint tokens or sessions itself.
func (s *Service) CheckPassword(ctx context.Context, rawEmail, plain string) (*user.User, error) {
	email := strings.ToLower(strings.TrimSpace(rawEmail))
	if _, locked := s.loginLockedUntil(ctx, email); locked {
		return nil, errs.ErrTooManyRequests.WithDetail("too many failed attempts — account temporarily locked")
	}
	u, err := s.users.GetByEmailGlobal(ctx, rawEmail)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			// Throttle unknown emails identically so probing can't distinguish
			// "no such account" from "wrong password" by behaviour.
			s.recordFailedLogin(ctx, email)
			return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
		}
		return nil, err
	}
	if u.Status != "active" && u.Status != "invited" {
		return nil, errs.ErrForbidden.WithDetail("account " + u.Status)
	}
	hash, err := s.users.PasswordHash(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if hash == "" || !password.Verify(hash, plain) {
		s.recordFailedLogin(ctx, email)
		return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
	}
	s.clearLoginAttempts(ctx, email)
	// Transparently upgrade legacy bcrypt / weak-param hashes to current
	// Argon2id on a successful login. Best-effort: never fail the login on it.
	if password.NeedsRehash(hash) {
		if nh, herr := password.Hash(plain); herr == nil {
			if _, uerr := s.pool.Exec(ctx,
				`UPDATE auth.password_credentials SET password_hash = $1 WHERE user_id = $2`,
				nh, u.ID); uerr != nil {
				slog.Warn("password rehash-on-login failed", "user_id", u.ID, "err", uerr)
			}
		}
	}
	return u, nil
}

// IssuePair creates a session, mints an access+refresh pair, and records
// an audit row labelled with the login method ("password", "magic_link",
// "invite_accept", "oidc", "passkey", "social", …). The audit row lives
// inside the session-insert transaction so analytics never see a session
// without its provenance event.
func (s *Service) IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*TokenPair, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	sessionID := uuid.New()
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	// uuid.Nil = tenant-less: store NULL (the zero UUID would violate the FK).
	var tenantArg any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		t := tenantID
		tenantArg = t
		tenantPtr = &t
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, $5)
	`, sessionID, userID, tenantArg, ipArg, ua); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueAccess(userID, tenantID, sessionID, "")
	if err != nil {
		return nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	refreshExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (session_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, sessionID, refreshHash, refreshExp); err != nil {
		return nil, err
	}
	if method == "" {
		method = "unknown"
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       "auth.login_succeeded",
		ResourceType: "session",
		ResourceID:   &sessionID,
		IP:           ip,
		UserAgent:    ua,
		Metadata:     map[string]any{"method": method},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: refreshRaw,
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantPtr,
	}, nil
}

// Refresh rotates the provided refresh token: the old row is marked used,
// a new one is inserted, and a fresh access token is signed. Reuse of an
// already-used token revokes the whole session (token theft mitigation)
// and emits an audit event + outbox event so notifications (email,
// webhook) can reach the user.
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (*TokenPair, error) {
	hash := tokens.HashRefresh(in.RefreshToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id         uuid.UUID
		sessionID  uuid.UUID
		usedAt     *time.Time
		expiresAt  time.Time
		sessionRev *time.Time
		userID     uuid.UUID
		tenantPtr  *uuid.UUID // NULL for a tenant-less session
	)
	row := tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
		       s.revoked_at, s.user_id, s.tenant_id
		FROM auth.refresh_tokens rt
		JOIN auth.sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt
	`, hash)
	if err := row.Scan(&id, &sessionID, &usedAt, &expiresAt, &sessionRev, &userID, &tenantPtr); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized.WithDetail("unknown refresh token")
		}
		return nil, err
	}
	if sessionRev != nil {
		return nil, errs.ErrUnauthorized.WithDetail("session revoked")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("refresh token expired")
	}
	// uuid.Nil = tenant-less session; preserved across refresh.
	var tenantID uuid.UUID
	if tenantPtr != nil {
		tenantID = *tenantPtr
	}
	if usedAt != nil {
		// Reuse — assume theft. Revoke the session, write an audit row,
		// and enqueue an outbox event so downstream notifiers (email,
		// webhook) can alert the user. All three happen atomically with
		// the revocation so a partial failure leaves no inconsistent
		// state.
		if err := s.handleRefreshReuse(ctx, tx, userID, tenantID, sessionID, id, in); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrUnauthorized.WithDetail("refresh token reuse — session revoked")
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	var newID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.refresh_tokens (session_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
	`, sessionID, newHash, newExp).Scan(&newID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.refresh_tokens SET used_at = NOW(), replaced_by = $1 WHERE id = $2
	`, newID, id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET last_seen_at = NOW() WHERE id = $1`, sessionID); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueAccess(userID, tenantID, sessionID, "")
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: newRaw,
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantPtr,
	}, nil
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

	tid := tenantID
	uid := userID
	sid := sessionID
	ae := audit.Event{
		TenantID:     &tid,
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
			"tenant_id":  tenantID,
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
	if _, err := tx.Exec(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`, sessionID); err != nil {
		return err
	}

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

func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL
	`, sessionID)
	return err
}

type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	IP         *string    `json:"ip"`
	UserAgent  *string    `json:"user_agent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	// Soft-deleted users keep their session rows for audit purposes but
	// must not surface them via admin or self-service listings. Filter
	// at the join rather than relying on the caller to know about
	// `users.deleted_at`.
	rows, err := s.pool.Query(ctx, `
		SELECT sess.id, sess.user_id, sess.tenant_id, host(sess.ip), sess.user_agent,
		       sess.created_at, sess.last_seen_at, sess.revoked_at
		FROM auth.sessions sess
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL
		ORDER BY sess.created_at DESC
		LIMIT 100
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TenantID, &s.IP, &s.UserAgent, &s.CreatedAt, &s.LastSeenAt, &s.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
