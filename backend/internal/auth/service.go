// Package auth handles login, refresh, logout, and session storage.
// Tokens are HS256 in dev; production should swap to RS256 with JWKS.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/outbox"
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
}

// Signup is the self-service onboarding endpoint. In one transaction it:
//
//  1. Creates an auto-generated "personal" tenant for the user.
//  2. Creates a user under that tenant with a password credential.
//  3. Creates an "owner" system role for the tenant and grants it every
//     platform permission currently in rbac.permissions.
//  4. Assigns the new user to the owner role.
//  5. Issues an access + refresh token pair so the caller is auto-logged in.
//
// The signup input is now tenant-less — the user provides only email +
// password (+ optional display name). They land in their personal tenant
// and can rename it or create additional ones from the admin UI.
//
// Errors:
//   - ErrConflict on duplicate email (globally unique)
//   - ErrUnprocessable on bad input
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	personalSlug, personalName := derivePersonalTenant(in.Email, in.DisplayName)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback(ctx)

	// 1) Tenant — personal workspace, slug auto-generated, plan = free.
	tenant := &TenantBrief{Slug: personalSlug, Name: personalName, Plan: "free", Region: "us-east-1"}
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, tenant.Slug, tenant.Name, tenant.Plan, tenant.Region).Scan(&tenant.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Extremely unlikely — slug collision on a 16-char hex suffix.
			return nil, nil, nil, errs.ErrConflict.WithDetail("personal tenant slug collision; retry")
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

// derivePersonalTenant generates a slug + name for the auto-created
// personal workspace. Slug is hex-suffixed so collisions are vanishingly
// rare; name falls back to the email local-part if no display_name was
// supplied.
func derivePersonalTenant(email, displayName string) (slug, name string) {
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	slug = "personal-" + suffix
	base := strings.TrimSpace(displayName)
	if base == "" {
		if at := strings.Index(email, "@"); at > 0 {
			base = email[:at]
		} else {
			base = "user"
		}
	}
	name = base + "'s workspace"
	return slug, name
}

func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	u, err := s.users.GetByEmailGlobal(ctx, in.Email)
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
