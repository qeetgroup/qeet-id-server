// Package agent provides first-class AI-agent identities: non-human principals
// that authenticate with a secret and receive SHORT-LIVED, scoped access tokens
// marked actor_type="agent" (plus an agent_id claim). Tokens are ephemeral by
// design — an agent re-mints rather than refreshing — and are signed by the
// same platform issuer, so they verify through the standard JWKS/RequireAuth
// path while remaining distinguishable from human and service principals
// (foundational for MCP-server authorization).
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/password"
	"github.com/qeetgroup/qeet-id/platform/tokens"
)

type Service struct {
	pool   *pgxpool.Pool
	issuer *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, issuer: issuer}
}

type Agent struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Scopes          []string  `json:"scopes"`
	TokenTTLSeconds int       `json:"token_ttl_seconds"`
	Disabled        bool      `json:"disabled"`
	CreatedAt       time.Time `json:"created_at"`
	// Secret is the plaintext credential, returned only once on create.
	Secret string `json:"secret,omitempty"`
}

// clampTTL keeps agent token lifetimes short (ephemeral): 60s..1h, default 10m.
func clampTTL(s int) int {
	if s <= 0 {
		return 600
	}
	if s < 60 {
		return 60
	}
	if s > 3600 {
		return 3600
	}
	return s
}

func newSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "agt_" + hex.EncodeToString(b), nil
}

func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, ttl int) (*Agent, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("name is required")
	}
	if scopes == nil {
		scopes = []string{}
	}
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, err
	}
	ttl = clampTTL(ttl)
	var a Agent
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.agents (tenant_id, name, secret_hash, scopes, token_ttl_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, scopes, token_ttl_seconds, created_at
	`, tenantID, name, hash, scopes, ttl).Scan(&a.ID, &a.Name, &a.Scopes, &a.TokenTTLSeconds, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	a.Secret = secret
	return &a, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, scopes, token_ttl_seconds, disabled_at, created_at
		FROM auth.agents WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Agent, 0)
	for rows.Next() {
		var a Agent
		var disabledAt *time.Time
		if err := rows.Scan(&a.ID, &a.Name, &a.Scopes, &a.TokenTTLSeconds, &disabledAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Disabled = disabledAt != nil
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM auth.agents WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// IssueToken authenticates an agent (id + secret) and mints a short-lived,
// scoped access token carrying actor_type="agent" + agent_id.
func (s *Service) IssueToken(ctx context.Context, agentID, secret string) (*TokenResponse, error) {
	id, err := uuid.Parse(agentID)
	if err != nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid agent_id")
	}
	var (
		tenantID   uuid.UUID
		secretHash string
		scopes     []string
		ttl        int
		disabledAt *time.Time
	)
	err = s.pool.QueryRow(ctx, `
		SELECT tenant_id, secret_hash, scopes, token_ttl_seconds, disabled_at
		FROM auth.agents WHERE id = $1
	`, id).Scan(&tenantID, &secretHash, &scopes, &ttl, &disabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown agent")
	}
	if err != nil {
		return nil, err
	}
	if disabledAt != nil {
		return nil, errs.ErrUnauthorized.WithDetail("agent disabled")
	}
	if !password.Verify(secretHash, secret) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid agent secret")
	}

	now := time.Now().UTC()
	exp := now.Add(time.Duration(clampTTL(ttl)) * time.Second)
	scope := strings.Join(scopes, " ")

	// Mirror the service-principal token shape (same issuer/audience so it
	// verifies on the standard path) but mark actor_type="agent" + agent_id.
	type agentClaims struct {
		TenantID  uuid.UUID `json:"tenant_id"`
		Scope     string    `json:"scope,omitempty"`
		ActorType string    `json:"actor_type"`
		AgentID   string    `json:"agent_id"`
		jwt.RegisteredClaims
	}
	claims := agentClaims{
		TenantID:  tenantID,
		Scope:     scope,
		ActorType: "agent",
		AgentID:   id.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer.JWTIssuer(),
			Audience:  jwt.ClaimStrings{s.issuer.JWTAudience()},
			Subject:   id.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	signed, err := s.issuer.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &TokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(exp).Seconds()),
		Scope:       scope,
	}, nil
}

// --- handlers ---

type Handler struct {
	Service *Service
}

// Mount registers tenant-scoped admin endpoints (require a user JWT/API key).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/agents", h.list)
	r.Post("/tenants/{tenantID}/agents", h.create)
	r.Delete("/tenants/{tenantID}/agents/{id}", h.del)
}

// MountPublic registers the agent token endpoint (agent-authenticated, no user
// session) — lives in the public group and is CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/agents/token", h.token)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name            string   `json:"name"`
		Scopes          []string `json:"scopes"`
		TokenTTLSeconds int      `json:"token_ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a, err := h.Service.Create(r.Context(), tenantID, in.Name, in.Scopes, in.TokenTTLSeconds)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	}
	// Also accept HTTP Basic (agent_id:secret), mirroring OAuth client auth.
	if u, p, ok := r.BasicAuth(); ok {
		in.AgentID, in.Secret = u, p
	} else if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.Service.IssueToken(r.Context(), in.AgentID, in.Secret)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
