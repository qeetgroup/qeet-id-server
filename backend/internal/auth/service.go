// Package auth handles login, refresh, logout, and session storage.
// Tokens are HS256 in dev; production should swap to RS256 with JWKS.
package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

type SignupInput struct {
	Email       string
	Password    string
	DisplayName string
	Tenant      SignupTenantInput
	IP          string
	UserAgent   string
}

type SignupTenantInput struct {
	Slug   string
	Name   string
	Plan   string
	Region string
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
}

// Signup is the self-service onboarding endpoint. In one transaction it:
//
//  1. Creates a new tenant from the provided slug/name/plan/region.
//  2. Creates a user under that tenant with a password credential.
//  3. Creates an "owner" system role for the tenant and grants it every
//     platform permission currently in rbac.permissions.
//  4. Assigns the new user to the owner role.
//  5. Issues an access + refresh token pair so the caller is auto-logged in.
//
// The user therefore becomes an admin of the tenant they just signed up
// for and can manage users, roles, branding, webhooks, etc. without any
// further bootstrapping.
//
// Errors:
//   - ErrConflict on duplicate tenant slug or duplicate email
//   - ErrUnprocessable on bad input
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	plan := strings.TrimSpace(in.Tenant.Plan)
	if plan == "" {
		plan = "free"
	}
	region := strings.TrimSpace(in.Tenant.Region)
	if region == "" {
		region = "us-east-1"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback(ctx)

	// 1) Tenant.
	tenant := &TenantBrief{Slug: strings.TrimSpace(in.Tenant.Slug), Name: in.Tenant.Name, Plan: plan, Region: region}
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, tenant.Slug, tenant.Name, tenant.Plan, tenant.Region).Scan(&tenant.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, nil, nil, errs.ErrConflict.WithDetail("tenant slug already exists")
		}
		return nil, nil, nil, err
	}

	// 2) User.
	var displayName any
	if in.DisplayName != "" {
		displayName = in.DisplayName
	}
	u := &user.User{TenantID: tenant.ID, Email: strings.TrimSpace(in.Email), Status: "active", Metadata: map[string]any{}}
	if in.DisplayName != "" {
		dn := in.DisplayName
		u.DisplayName = &dn
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`, u.TenantID, u.Email, displayName).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, nil, nil, errs.ErrConflict.WithDetail("email already exists for tenant")
		}
		return nil, nil, nil, err
	}

	// 3) Password credential.
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash)
		VALUES ($1, $2)
	`, u.ID, hash); err != nil {
		return nil, nil, nil, err
	}

	// 4) Owner role for this tenant.
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, description, is_system)
		VALUES ($1, 'owner', 'Tenant owner — full access', TRUE)
		RETURNING id
	`, tenant.ID).Scan(&roleID); err != nil {
		return nil, nil, nil, err
	}

	// 5) Grant every platform permission to the owner role.
	if _, err := tx.Exec(ctx, `
		INSERT INTO rbac.role_permissions (role_id, permission_id)
		SELECT $1, id FROM rbac.permissions
	`, roleID); err != nil {
		return nil, nil, nil, err
	}

	// 6) Assign the user to the owner role.
	if _, err := tx.Exec(ctx, `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id)
		VALUES ($1, $2, $3)
	`, u.ID, tenant.ID, roleID); err != nil {
		return nil, nil, nil, err
	}

	// 7) Session + access + refresh token, all in the same tx so signup
	// is fully atomic.
	sessionID := uuid.New()
	var ipArg any
	if in.IP != "" {
		ipArg = in.IP
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, $5)
	`, sessionID, u.ID, tenant.ID, ipArg, in.UserAgent); err != nil {
		return nil, nil, nil, err
	}
	access, exp, err := s.tokens.IssueAccess(u.ID, tenant.ID, sessionID, "")
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
	}, u, tenant, nil
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
