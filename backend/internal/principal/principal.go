// Package principal manages OAuth-style service principals — non-human
// callers that authenticate via client_credentials grant and receive a
// short-lived service JWT scoped to a single tenant.
package principal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
)

type Service struct {
	pool   *pgxpool.Pool
	issuer *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, issuer: issuer}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type Principal struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	DisabledAt *time.Time `json:"disabled_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type CreateInput struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scopes      []string  `json:"scopes"`
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Principal, string, error) {
	raw, _, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	hash, err := password.Hash(raw)
	if err != nil {
		return nil, "", err
	}
	var p Principal
	err = tx.QueryRow(ctx, `
		INSERT INTO auth.service_principals (tenant_id, name, description, secret_hash, scopes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, tenant_id, name, scopes, disabled_at, created_at
	`, in.TenantID, in.Name, in.Description, hash, in.Scopes).
		Scan(&p.ID, &p.TenantID, &p.Name, &p.Scopes, &p.DisabledAt, &p.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	return &p, raw, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Principal, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, scopes, disabled_at, created_at
		FROM auth.service_principals WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Principal
	for rows.Next() {
		var p Principal
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Scopes, &p.DisabledAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Disable marks a service principal disabled. Returns the (tenantID,
// name) for the audit row so the caller doesn't have to re-query.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, string, error) {
	var tenantID uuid.UUID
	var name string
	err := tx.QueryRow(ctx, `
		UPDATE auth.service_principals SET disabled_at = NOW()
		WHERE id = $1 AND disabled_at IS NULL
		RETURNING tenant_id, name
	`, id).Scan(&tenantID, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return tenantID, name, nil
}

type TokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	Scope       string    `json:"scope"`
}

// IssueClientCredentials verifies (client_id, client_secret) and returns
// a service JWT signed with the platform issuer's secret.
func (s *Service) IssueClientCredentials(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	pid, err := uuid.Parse(clientID)
	if err != nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid client_id")
	}
	var (
		id, tenantID uuid.UUID
		secretHash   string
		scopes       []string
		disabledAt   *time.Time
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, secret_hash, scopes, disabled_at
		FROM auth.service_principals WHERE id = $1
	`, pid).Scan(&id, &tenantID, &secretHash, &scopes, &disabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown client")
	}
	if err != nil {
		return nil, err
	}
	if disabledAt != nil {
		return nil, errs.ErrUnauthorized.WithDetail("client disabled")
	}
	if !password.Verify(secretHash, clientSecret) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid client secret")
	}
	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL())
	scope := joinScopes(scopes)

	// Reuse the platform issuer secret/issuer/audience for compatibility
	// with the same verifier the user endpoints use. ActorType comes from
	// a custom claim so the verifier can distinguish.
	type svcClaims struct {
		TenantID  uuid.UUID `json:"tenant_id"`
		Scope     string    `json:"scope,omitempty"`
		ActorType string    `json:"actor_type"`
		jwt.RegisteredClaims
	}
	claims := svcClaims{
		TenantID:  tenantID,
		Scope:     scope,
		ActorType: "service",
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
		ExpiresAt:   exp,
		Scope:       scope,
	}, nil
}

func joinScopes(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/service-principals", h.create)
	r.Get("/tenants/{tenantID}/service-principals", h.list)
	r.Delete("/service-principals/{id}", h.disable)
}

func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/oauth/token", h.tokenEndpoint)
}

// auditActor mirrors the helper used in rbac/mfa.
func auditActor(r *http.Request) (*uuid.UUID, string) {
	pp := httpx.PrincipalFromCtx(r.Context())
	if pp == nil {
		return nil, "system"
	}
	at := pp.ActorType
	if at == "" {
		at = "user"
	}
	return pp.UserID, at
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	p, secret, err := h.Service.Create(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tenantID := p.TenantID
	resID := p.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "service_principal.created",
		ResourceType: "service_principal",
		ResourceID:   &resID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"name": p.Name, "scopes": p.Scopes},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"service_principal": p,
		"client_id":         p.ID,
		"client_secret":     secret,
		"warning":           "secret shown once",
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	tenantID, name, err := h.Service.Disable(ctx, tx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	resID := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "service_principal.disabled",
		ResourceType: "service_principal",
		ResourceID:   &resID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"name": name},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tokenEndpoint implements RFC 6749 client_credentials grant. Form-encoded
// per spec, accepts grant_type=client_credentials with client_id and
// client_secret either in the body or in Basic auth.
func (h *Handler) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("unsupported grant_type"))
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	if clientID == "" || clientSecret == "" {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("client credentials required"))
		return
	}
	resp, err := h.Service.IssueClientCredentials(r.Context(), clientID, clientSecret)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
