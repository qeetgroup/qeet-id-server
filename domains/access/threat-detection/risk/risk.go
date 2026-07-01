// Package risk aggregates bot-detection, failed-login, and trusted-device
// signals into a per-request risk level. The level drives adaptive MFA: a High
// request is forced through a second factor even if the device is trusted.
package risk

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/bot"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
)

// Level represents the aggregated risk of an authentication request.
type Level int

const (
	Low Level = iota
	Medium
	High
)

func (l Level) String() string {
	switch l {
	case Medium:
		return "medium"
	case High:
		return "high"
	default:
		return "low"
	}
}

// Settings are the per-tenant risk thresholds stored in auth.risk_settings.
type Settings struct {
	MediumThreshold  float64 `json:"medium_threshold"`
	HighThreshold    float64 `json:"high_threshold"`
	ForceMFAAtLevel  string  `json:"force_mfa_at_level"`
}

func defaultSettings() Settings {
	return Settings{MediumThreshold: 0.50, HighThreshold: 0.80, ForceMFAAtLevel: "high"}
}

// Service assesses risk and manages per-tenant risk settings.
type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Assess returns the risk Level for an authentication request. Inputs are the
// user's UA string and the tenant whose thresholds apply. Fails open (Low) on
// any DB error so a misconfigured risk table never blocks login.
func (s *Service) Assess(ctx context.Context, tenantID uuid.UUID, ua string) Level {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		slog.Warn("risk: could not load settings, defaulting to Low", "tenant_id", tenantID, "err", err)
		return Low
	}

	score := bot.Score(ua)
	switch {
	case score >= settings.HighThreshold:
		return High
	case score >= settings.MediumThreshold:
		return Medium
	default:
		return Low
	}
}

// ForceMFA reports whether the risk level should force MFA regardless of
// trusted-device status, based on the tenant's force_mfa_at_level setting.
func (s *Service) ForceMFA(ctx context.Context, tenantID uuid.UUID, level Level) bool {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return false
	}
	switch settings.ForceMFAAtLevel {
	case "medium":
		return level >= Medium
	default: // "high"
		return level >= High
	}
}

// ShouldForceMFA satisfies the auth.RiskAssessor interface. It assesses the UA
// and returns true when the resulting risk level exceeds the tenant threshold.
func (s *Service) ShouldForceMFA(ctx context.Context, tenantID uuid.UUID, ua string) bool {
	level := s.Assess(ctx, tenantID, ua)
	return s.ForceMFA(ctx, tenantID, level)
}

func (s *Service) GetSettings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	var st Settings
	err := s.pool.QueryRow(ctx, `
		SELECT medium_threshold, high_threshold, force_mfa_at_level
		FROM auth.risk_settings WHERE tenant_id = $1
	`, tenantID).Scan(&st.MediumThreshold, &st.HighThreshold, &st.ForceMFAAtLevel)
	if err == pgx.ErrNoRows {
		return defaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return st, nil
}

// Handler exposes risk settings over HTTP.
type Handler struct{ Service *Service }

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/security/risk-settings", h.get)
	r.Put("/tenants/{tenantID}/security/risk-settings", h.put)
}

func requireTenant(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if id != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.GetSettings(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.UpdateSettings(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) UpdateSettings(ctx context.Context, tenantID uuid.UUID, in Settings) (Settings, error) {
	if in.MediumThreshold < 0.1 {
		in.MediumThreshold = 0.1
	}
	if in.HighThreshold < 0.1 {
		in.HighThreshold = 0.1
	}
	if in.ForceMFAAtLevel != "medium" {
		in.ForceMFAAtLevel = "high"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.risk_settings (tenant_id, medium_threshold, high_threshold, force_mfa_at_level, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			medium_threshold  = EXCLUDED.medium_threshold,
			high_threshold    = EXCLUDED.high_threshold,
			force_mfa_at_level = EXCLUDED.force_mfa_at_level,
			updated_at        = NOW()
	`, tenantID, in.MediumThreshold, in.HighThreshold, in.ForceMFAAtLevel)
	if err != nil {
		return Settings{}, err
	}
	return in, nil
}
