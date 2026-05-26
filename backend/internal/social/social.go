// Package social manages tenant-configured external identity providers
// (Google, GitHub, Microsoft, ...) and the externally-issued identity
// rows that link to a Qeet user. The OAuth/OIDC exchange ceremony is a
// stub — callbacks return 501 until per-provider clients are wired.
package social

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Provider struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	DiscoveryURL *string   `json:"discovery_url"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type ExternalIdentity struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Email    *string   `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

type CreateProviderInput struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	DiscoveryURL string    `json:"discovery_url"`
}

func (s *Service) UpsertProvider(ctx context.Context, in CreateProviderInput) (*Provider, error) {
	var p Provider
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
		VALUES ($1, $2, $3, $4, NULLIF($5,''))
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			client_secret = EXCLUDED.client_secret,
			discovery_url = EXCLUDED.discovery_url,
			enabled = TRUE
		RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at
	`, in.TenantID, in.Provider, in.ClientID, in.ClientSecret, in.DiscoveryURL).
		Scan(&p.ID, &p.TenantID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, provider, client_id, discovery_url, enabled, created_at
		FROM tenant.social_providers WHERE tenant_id = $1 ORDER BY provider
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) ListIdentities(ctx context.Context, userID uuid.UUID) ([]ExternalIdentity, error) {
	// Mirror users.deleted_at — a soft-deleted user's linked identities
	// must not surface in self-service or admin lookups.
	rows, err := s.pool.Query(ctx, `
		SELECT ei.id, ei.user_id, ei.tenant_id, ei.provider, ei.subject, ei.email, ei.linked_at
		FROM "user".external_identities ei
		JOIN "user".users u ON u.id = ei.user_id
		WHERE ei.user_id = $1 AND u.deleted_at IS NULL
		ORDER BY ei.linked_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExternalIdentity
	for rows.Next() {
		var e ExternalIdentity
		if err := rows.Scan(&e.ID, &e.UserID, &e.TenantID, &e.Provider, &e.Subject, &e.Email, &e.LinkedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Service) Unlink(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM "user".external_identities WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/social/providers", h.upsertProvider)
	r.Get("/tenants/{tenantID}/social/providers", h.listProviders)
	r.Get("/users/{userID}/social/identities", h.listIdentities)
	r.Delete("/social/identities/{id}", h.unlink)
	// OAuth ceremony — wires up per-provider exchange in a later iteration.
	r.Get("/social/{provider}/start", h.start)
	r.Get("/social/{provider}/callback", h.callback)
}

func (h *Handler) upsertProvider(w http.ResponseWriter, r *http.Request) {
	var in CreateProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.UpsertProvider(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) listProviders(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Service.ListProviders(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) listIdentities(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	out, err := h.Service.ListIdentities(r.Context(), uid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) unlink(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Unlink(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, &errs.Error{
		Code:    "not_implemented",
		Status:  http.StatusNotImplemented,
		Message: "social OAuth start pending per-provider client config",
	})
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, &errs.Error{
		Code:    "not_implemented",
		Status:  http.StatusNotImplemented,
		Message: "social OAuth callback pending per-provider client config",
	})
}
