// Package risk aggregates bot-detection, impossible-travel, and
// device-reputation signals into a per-request risk level. The level drives
// adaptive MFA: a High request is forced through a second factor even if the
// device is trusted.
package risk

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/bot"
	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/risk/dbgen"
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
	MediumThreshold float64 `json:"medium_threshold"`
	HighThreshold   float64 `json:"high_threshold"`
	ForceMFAAtLevel string  `json:"force_mfa_at_level"`
	// ImpossibleTravelEnabled flags a login from a different country than the
	// user's last-seen one, sooner than MinTravelHours could plausibly allow.
	// Off by default: it needs a country signal (see Assess) to do anything,
	// and — like any new heuristic — shouldn't start affecting logins until a
	// tenant opts in.
	ImpossibleTravelEnabled bool    `json:"impossible_travel_enabled"`
	MinTravelHours          float64 `json:"min_travel_hours"`
	// DeviceReputationEnabled flags a login from a browser+OS combination
	// never seen before for this user.
	DeviceReputationEnabled bool `json:"device_reputation_enabled"`
}

func defaultSettings() Settings {
	return Settings{
		MediumThreshold: 0.50, HighThreshold: 0.80, ForceMFAAtLevel: "high",
		MinTravelHours: 3,
	}
}

// Additive score contributions for the two new signals, on top of the
// existing bot.Score(ua) base — "additive checks on the existing threshold
// engine," not a reweighting of it. Impossible travel is treated as the
// stronger signal (few legitimate reasons to cross a border in under
// MinTravelHours); a brand-new device is common (new phone, cleared
// cookies) so contributes less.
const (
	impossibleTravelBump = 0.5
	newDeviceBump        = 0.25
)

// computeLevel is Assess's pure decision core, split out so it's unit-testable
// without a database: given the already-resolved signals, what Level results.
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

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

// Assess returns the risk Level for an authentication request, and records
// this login's device/country into the user's history for future
// assessments. country is resolved by the caller (e.g. from a trusted
// upstream proxy header); pass "" when no geo signal is available — an
// impossible-travel check with no country data simply never fires.
// Fails open (Low) on any DB error so a misconfigured risk table never
// blocks login.
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

	s.recordLogin(ctx, tenantID, userID, dk, country)

	return computeLevel(settings, bot.Score(ua), impossibleTravel, newDevice)
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

// ShouldForceMFA satisfies the auth.RiskAssessor interface. It assesses the
// request and returns true when the resulting risk level exceeds the
// tenant's force-MFA threshold.
func (s *Service) ShouldForceMFA(ctx context.Context, tenantID, userID uuid.UUID, ip, ua, country string) bool {
	level := s.Assess(ctx, tenantID, userID, ip, ua, country)
	return s.ForceMFA(ctx, tenantID, level)
}

func (s *Service) GetSettings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	row, err := s.q.GetRiskSettings(ctx, tenantID)
	if err == pgx.ErrNoRows {
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
