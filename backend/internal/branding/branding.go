// Package branding stores per-tenant theming and custom-domain settings.
package branding

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Branding struct {
	TenantID         uuid.UUID      `json:"tenant_id"`
	LogoURL          *string        `json:"logo_url"`
	PrimaryColor     *string        `json:"primary_color"`
	SecondaryColor   *string        `json:"secondary_color"`
	CustomDomain     *string        `json:"custom_domain"`
	EmailFromName    *string        `json:"email_from_name"`
	EmailFromAddress *string        `json:"email_from_address"`
	Settings         map[string]any `json:"settings"`
}

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Branding, error) {
	var b Branding
	var settings []byte
	err := r.pool.QueryRow(ctx, `
		SELECT tenant_id, logo_url, primary_color, secondary_color,
		       custom_domain, email_from_name, email_from_address, settings
		FROM tenant.branding WHERE tenant_id = $1
	`, tenantID).Scan(&b.TenantID, &b.LogoURL, &b.PrimaryColor, &b.SecondaryColor,
		&b.CustomDomain, &b.EmailFromName, &b.EmailFromAddress, &settings)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Branding{TenantID: tenantID, Settings: map[string]any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &b.Settings)
	}
	if b.Settings == nil {
		b.Settings = map[string]any{}
	}
	return &b, nil
}

func (r *Repository) Upsert(ctx context.Context, b Branding) error {
	settings, _ := json.Marshal(b.Settings)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO tenant.branding (
			tenant_id, logo_url, primary_color, secondary_color, custom_domain,
			email_from_name, email_from_address, settings
		) VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE(NULLIF($8::jsonb,'null'::jsonb), '{}'::jsonb))
		ON CONFLICT (tenant_id) DO UPDATE SET
			logo_url = EXCLUDED.logo_url,
			primary_color = EXCLUDED.primary_color,
			secondary_color = EXCLUDED.secondary_color,
			custom_domain = EXCLUDED.custom_domain,
			email_from_name = EXCLUDED.email_from_name,
			email_from_address = EXCLUDED.email_from_address,
			settings = EXCLUDED.settings,
			updated_at = NOW()
	`, b.TenantID, b.LogoURL, b.PrimaryColor, b.SecondaryColor, b.CustomDomain,
		b.EmailFromName, b.EmailFromAddress, settings)
	return err
}

type Handler struct {
	Repo *Repository
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/branding", h.get)
	r.Put("/tenants/{tenantID}/branding", h.put)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	b, err := h.Repo.Get(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, b)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	var in Branding
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tid
	if err := h.Repo.Upsert(r.Context(), in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, in)
}
