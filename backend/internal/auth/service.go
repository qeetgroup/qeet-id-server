// Package auth handles login, refresh, logout, and session storage.
// Tokens are HS256 in dev; production should swap to RS256 with JWKS.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
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
	TenantID  uuid.UUID
	Email     string
	Password  string
	IP        string
	UserAgent string
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	SessionID    uuid.UUID `json:"session_id"`
	UserID       uuid.UUID `json:"user_id"`
}

func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	u, err := s.users.GetByEmail(ctx, in.TenantID, in.Email)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
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
	if hash == "" || !password.Verify(hash, in.Password) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
	}
	return s.IssuePair(ctx, u.ID, u.TenantID, in.IP, in.UserAgent)
}

func (s *Service) IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*TokenPair, error) {
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, $5)
	`, sessionID, userID, tenantID, ipArg, ua); err != nil {
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
	}, nil
}

// Refresh rotates the provided refresh token: the old row is marked used,
// a new one is inserted, and a fresh access token is signed. Reuse of an
// already-used token revokes the whole session (token theft mitigation).
func (s *Service) Refresh(ctx context.Context, raw string) (*TokenPair, error) {
	hash := tokens.HashRefresh(raw)

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
		tenantID   uuid.UUID
	)
	row := tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
		       s.revoked_at, s.user_id, s.tenant_id
		FROM auth.refresh_tokens rt
		JOIN auth.sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt
	`, hash)
	if err := row.Scan(&id, &sessionID, &usedAt, &expiresAt, &sessionRev, &userID, &tenantID); err != nil {
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
	if usedAt != nil {
		// Reuse — assume theft and revoke the entire session.
		_, _ = tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, sessionID)
		_ = tx.Commit(ctx)
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
	}, nil
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
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, tenant_id, host(ip), user_agent, created_at, last_seen_at, revoked_at
		FROM auth.sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
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
