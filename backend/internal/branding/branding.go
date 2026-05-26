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

	"github.com/qeetgroup/qeet-identity/internal/audit"
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

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

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

func (r *Repository) Upsert(ctx context.Context, tx pgx.Tx, b Branding) error {
	settings, _ := json.Marshal(b.Settings)
	_, err := tx.Exec(ctx, `
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

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
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
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Repo.Upsert(ctx, tx, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := tid
	meta := map[string]any{}
	if in.CustomDomain != nil {
		meta["custom_domain"] = *in.CustomDomain
	}
	if in.PrimaryColor != nil {
		meta["primary_color"] = *in.PrimaryColor
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &target,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "branding.updated",
		ResourceType: "tenant",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, in)
}
