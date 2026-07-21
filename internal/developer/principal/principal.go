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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/principal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

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
	row, err := s.q.WithTx(tx).CreateServicePrincipal(ctx, dbgen.CreateServicePrincipalParams{
		TenantID:    in.TenantID,
		Name:        in.Name,
		Description: in.Description,
		SecretHash:  hash,
		Scopes:      in.Scopes,
	})
	if err != nil {
		return nil, "", err
	}
	p := &Principal{
		ID: row.ID, TenantID: row.TenantID, Name: row.Name,
		Scopes: row.Scopes, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
	}
	return p, raw, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Principal, error) {
	rows, err := s.q.ListServicePrincipals(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Principal, 0, len(rows))
	for _, row := range rows {
		out = append(out, Principal{
			ID: row.ID, TenantID: row.TenantID, Name: row.Name,
			Scopes: row.Scopes, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// Disable marks a service principal disabled. Returns the (tenantID,
// name) for the audit row so the caller doesn't have to re-query.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, string, error) {
	row, err := s.q.WithTx(tx).DisableServicePrincipal(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return row.TenantID, row.Name, nil
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
	row, err := s.q.GetServicePrincipalForAuth(ctx, pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown client")
	}
	if err != nil {
		return nil, err
	}
	if row.DisabledAt.Valid {
		return nil, errs.ErrUnauthorized.WithDetail("client disabled")
	}
	if !password.Verify(row.SecretHash, clientSecret) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid client secret")
	}
	id, tenantID, scopes := row.ID, row.TenantID, row.Scopes
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
