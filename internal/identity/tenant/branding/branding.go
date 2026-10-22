// Package branding stores per-tenant theming, custom-domain and email-sender
// settings.
package branding

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/dbutil"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q    *dbgen.Queries
	gate PlanGate
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// PlanGate reports whether a boolean plan feature is in the tenant's plan.
// Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate sets the plan-feature gate (nil allows all features).
func (r *Repository) SetPlanGate(g PlanGate) { r.gate = g }

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

func toDomain(tenantID uuid.UUID, row dbgen.GetBrandingRow) *Branding {
	return &Branding{
		TenantID:         row.TenantID,
		LogoURL:          row.LogoUrl,
		PrimaryColor:     row.PrimaryColor,
		SecondaryColor:   row.SecondaryColor,
		CustomDomain:     row.CustomDomain,
		EmailFromName:    row.EmailFromName,
		EmailFromAddress: row.EmailFromAddress,
		Settings:         dbutil.Metadata(row.Settings),
	}
}

func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Branding, error) {
	row, err := r.q.GetBranding(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Branding{TenantID: tenantID, Settings: map[string]any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return toDomain(tenantID, row), nil
}

// LoginBranding returns the tenant's hosted-login logo and colors as plain
// strings, empty when unset or on error. It satisfies oidc.BrandingLister,
// which takes primitives so federation doesn't depend on this package.
func (r *Repository) LoginBranding(ctx context.Context, tenantID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string) {
	b, err := r.Get(ctx, tenantID)
	if err != nil || b == nil {
		return "", "", "", ""
	}
	return loginAppearance(b)
}

func loginAppearance(b *Branding) (logoURL, primaryColor, secondaryColor, backgroundColor string) {
	if b.LogoURL != nil {
		logoURL = *b.LogoURL
	}
	if b.PrimaryColor != nil {
		primaryColor = *b.PrimaryColor
	}
	if b.SecondaryColor != nil {
		secondaryColor = *b.SecondaryColor
	}
	if value, ok := b.Settings["background_color"].(string); ok && colorPattern.MatchString(value) {
		backgroundColor = value
	}
	return logoURL, primaryColor, secondaryColor, backgroundColor
}

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

const maxBrandingBodyBytes = int64(3 << 20)

func decodeBranding(r *http.Request) (Branding, error) {
	var in Branding
	if err := httpx.DecodeJSONLimit(r, &in, maxBrandingBodyBytes); err != nil {
		return Branding{}, err
	}
	return in, normalizeAppearance(&in)
}

func normalizeAppearance(b *Branding) error {
	if b.LogoURL != nil && strings.HasPrefix(*b.LogoURL, "data:") {
		header, content, found := strings.Cut(*b.LogoURL, ",")
		if !found || (header != "data:image/png;base64" && header != "data:image/jpeg;base64" && header != "data:image/webp;base64" && header != "data:image/svg+xml;base64") {
			return errs.ErrBadRequest.WithDetail("logo must be a PNG, JPEG, WEBP or SVG image")
		}
		if len(content) > base64.StdEncoding.EncodedLen(2<<20) {
			return errs.ErrRequestBodyTooLarge
		}
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil || len(decoded) == 0 {
			return errs.ErrBadRequest.WithDetail("logo data is invalid")
		}
		if len(decoded) > 2<<20 {
			return errs.ErrRequestBodyTooLarge
		}
	}
	if value, exists := b.Settings["email_reply_to"]; exists {
		address, ok := value.(string)
		if !ok {
			return errs.ErrBadRequest.WithDetail("email_reply_to must be an email address")
		}
		address = strings.TrimSpace(address)
		if address != "" {
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address || strings.ContainsAny(address, "\r\n") {
				return errs.ErrBadRequest.WithDetail("email_reply_to must be a single email address")
			}
		}
		b.Settings["email_reply_to"] = address
	}
	if b.EmailFromName != nil && strings.ContainsAny(*b.EmailFromName, "\r\n") {
		return errs.ErrBadRequest.WithDetail("email_from_name must not contain line breaks")
	}
	if value, exists := b.Settings["background_color"]; exists {
		color, ok := value.(string)
		if !ok {
			return errs.ErrBadRequest.WithDetail("background_color must be a hex color")
		}
		color = strings.ToLower(strings.TrimSpace(color))
		if color != "" && !colorPattern.MatchString(color) {
			return errs.ErrBadRequest.WithDetail("background_color must be a six-digit hex color")
		}
		b.Settings["background_color"] = color
	}
	return nil
}

// Upsert persists branding. The INSERT ON CONFLICT uses a COALESCE/NULLIF
// expression for the JSONB settings column that sqlc cannot parse reliably, so
// this method stays hand-written on the caller-supplied pgx.Tx.
func (r *Repository) Upsert(ctx context.Context, tx pgx.Tx, b Branding) error {
	if err := normalizeAppearance(&b); err != nil {
		return err
	}
	// Plan gate: custom branding (logo, colors, custom email sender) is a paid feature.
	if r.gate != nil {
		ok, err := r.gate.FeatureAllowed(ctx, b.TenantID, "custom_branding")
		if err != nil {
			return err
		}
		if !ok {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "custom_branding"})
		}
	}
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
	in, err := decodeBranding(r)
	if err != nil {
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
