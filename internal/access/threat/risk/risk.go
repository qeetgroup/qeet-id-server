// Package risk combines bot-detection, impossible-travel and device-reputation
// signals into a per-request risk level. A level at or above the tenant's
// force-MFA level sends the sign-in through a second factor, even from a
// trusted device.
package risk

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Level represents the aggregated risk of an authentication request.
type Level int

const (
	Low Level = iota
	Medium
	High
)

// String returns the level's name.
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
// ImpossibleTravelEnabled flags a sign-in from a new country sooner than
// MinTravelHours after the last; DeviceReputationEnabled flags a browser-OS
// pair never seen for the user. Both are off until a tenant opts in.
type Settings struct {
	MediumThreshold         float64 `json:"medium_threshold"`
	HighThreshold           float64 `json:"high_threshold"`
	ForceMFAAtLevel         string  `json:"force_mfa_at_level"`
	ImpossibleTravelEnabled bool    `json:"impossible_travel_enabled"`
	MinTravelHours          float64 `json:"min_travel_hours"`
	DeviceReputationEnabled bool    `json:"device_reputation_enabled"`
}

func defaultSettings() Settings {
	return Settings{
		MediumThreshold: 0.50, HighThreshold: 0.80, ForceMFAAtLevel: "high",
		MinTravelHours: 3,
	}
}

// Score added to bot.Score(ua) for each signal. Impossible travel weighs more:
// a new device is common (new phone, cleared cookies).
const (
	impossibleTravelBump = 0.5
	newDeviceBump        = 0.25
)

// computeLevel returns the Level for already-resolved signals; Assess's
// decision without the database.
func computeLevel(settings Settings, botScore float64, impossibleTravel, newDevice bool) Level {
	score := botScore
	if impossibleTravel {
		score += impossibleTravelBump
	}
	if newDevice {
		score += newDeviceBump
	}
	if score > 1 {
		score = 1
	}
	switch {
	case score >= settings.HighThreshold:
		return High
	case score >= settings.MediumThreshold:
		return Medium
	default:
		return Low
	}
}

// Service assesses risk and manages per-tenant risk settings.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the risk setting service.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

// Assess returns the risk Level of a sign-in against earlier completed ones,
// which RecordSignIn adds. country "" disables the impossible-travel check.
// Database errors fail open (Low, or the signal is skipped), so a broken risk
// table never blocks sign-in.
func (s *Service) Assess(ctx context.Context, tenantID, userID uuid.UUID, ip, ua, country string) Level {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		slog.Warn("risk: could not load settings, defaulting to Low", "tenant_id", tenantID, "err", err)
		return Low
	}

	var impossibleTravel, newDevice bool
	dk := deviceKey(ua)

	if settings.ImpossibleTravelEnabled && country != "" {
		lastCountry, lastSeenAt, ok := s.lastCountry(ctx, tenantID, userID)
		if ok && lastCountry != country {
			elapsed := time.Since(lastSeenAt).Hours()
			if elapsed < settings.MinTravelHours {
				impossibleTravel = true
			}
		}
	}
	if settings.DeviceReputationEnabled {
		seen, err := s.deviceSeenBefore(ctx, tenantID, userID, dk)
		if err == nil && !seen {
			newDevice = true
		}
	}

	return computeLevel(settings, bot.Score(ua), impossibleTravel, newDevice)
}

// RecordSignIn records a completed sign-in's device and country for later
// assessments. A sign-in still to meet a challenge, or refused, is not
// recorded, so asking again is assessed the same.
func (s *Service) RecordSignIn(ctx context.Context, tenantID, userID uuid.UUID, ua, country string) {
	s.recordLogin(ctx, tenantID, userID, deviceKey(ua), country)
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

// ShouldForceMFA satisfies auth.RiskAssessor: it assesses the request, without
// recording it, and reports whether its level reaches the tenant's force-MFA
// level.
func (s *Service) ShouldForceMFA(ctx context.Context, tenantID, userID uuid.UUID, ip, ua, country string) bool {
	level := s.Assess(ctx, tenantID, userID, ip, ua, country)
	return s.ForceMFA(ctx, tenantID, level)
}

// GetSettings returns the tenant's risk settings.
func (s *Service) GetSettings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	row, err := s.q.GetRiskSettings(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Settings{
		MediumThreshold:         row.MediumThreshold,
		HighThreshold:           row.HighThreshold,
		ForceMFAAtLevel:         row.ForceMfaAtLevel,
		ImpossibleTravelEnabled: row.ImpossibleTravelEnabled,
		MinTravelHours:          row.MinTravelHours,
		DeviceReputationEnabled: row.DeviceReputationEnabled,
	}, nil
}

// Handler exposes risk settings over HTTP.
type Handler struct{ Service *Service }

// Mount registers the risk setting routes on r.
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

// UpdateSettings stores the tenant's risk settings.
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
	if in.MinTravelHours <= 0 {
		in.MinTravelHours = defaultSettings().MinTravelHours
	}
	if err := s.q.UpsertRiskSettings(ctx, dbgen.UpsertRiskSettingsParams{
		TenantID:                tenantID,
		MediumThreshold:         in.MediumThreshold,
		HighThreshold:           in.HighThreshold,
		ForceMfaAtLevel:         in.ForceMFAAtLevel,
		ImpossibleTravelEnabled: in.ImpossibleTravelEnabled,
		MinTravelHours:          in.MinTravelHours,
		DeviceReputationEnabled: in.DeviceReputationEnabled,
	}); err != nil {
		return Settings{}, err
	}
	return in, nil
}
