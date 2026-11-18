// Package risk combines bot-detection, impossible-travel and device-reputation
// signals into a per-request risk level. A level at or above the organization's
// force-MFA level sends the sign-in through a second factor, even from a
// trusted device.
package risk

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
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

// Settings are the per-organization risk thresholds stored in auth.risk_settings.
// ImpossibleTravelEnabled flags a sign-in from a new country sooner than
// MinTravelHours after the last; DeviceReputationEnabled flags a browser-OS
// pair never seen for the user. Both are off until an organization opts in.
type Settings struct {
	MediumThreshold         float64 `json:"medium_threshold"`
	HighThreshold           float64 `json:"high_threshold"`
	ForceMFAAtLevel         string  `json:"force_mfa_at_level"`
	ImpossibleTravelEnabled bool    `json:"impossible_travel_enabled"`
	MinTravelHours          float64 `json:"min_travel_hours"`
	DeviceReputationEnabled bool    `json:"device_reputation_enabled"`

	// Read-only, ignored on update: whether this deployment names a trusted
	// country header, and when this instance last read a country from it.
	// Without one, impossible travel never fires.
	CountryHeaderConfigured bool       `json:"country_header_configured"`
	CountryLastSeenAt       *time.Time `json:"country_last_seen_at"`
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

// Service assesses risk and manages per-organization risk settings.
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
func (s *Service) Assess(ctx context.Context, organizationID, userID uuid.UUID, ip, ua, country string) Level {
	settings, err := s.GetSettings(ctx, organizationID)
	if err != nil {
		slog.Warn("risk: could not load settings, defaulting to Low", "organization_id", organizationID, "err", err)
		return Low
	}

	var impossibleTravel, newDevice bool
	dk := DeviceKey(ua)

	if settings.ImpossibleTravelEnabled && country != "" {
		lastCountry, lastSeenAt, ok := s.lastCountry(ctx, organizationID, userID)
		if ok && lastCountry != country {
			elapsed := time.Since(lastSeenAt).Hours()
			if elapsed < settings.MinTravelHours {
				impossibleTravel = true
			}
		}
	}
	if settings.DeviceReputationEnabled {
		seen, err := s.deviceSeenBefore(ctx, organizationID, userID, dk)
		if err == nil && !seen {
			newDevice = true
		}
	}

	return computeLevel(settings, bot.Score(ua), impossibleTravel, newDevice)
}

// RecordSignIn records a completed sign-in's device and country for later
// assessments. A sign-in still to meet a challenge, or refused, is not
// recorded, so asking again is assessed the same.
func (s *Service) RecordSignIn(ctx context.Context, organizationID, userID uuid.UUID, ua, country string) {
	s.recordLogin(ctx, organizationID, userID, DeviceKey(ua), country)
}

// ForceMFA reports whether the risk level should force MFA regardless of
// trusted-device status, based on the organization's force_mfa_at_level setting.
func (s *Service) ForceMFA(ctx context.Context, organizationID uuid.UUID, level Level) bool {
	settings, err := s.GetSettings(ctx, organizationID)
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

// ShouldForceMFA satisfies authentication.RiskAssessor: it assesses the request, without
// recording it, and reports whether its level reaches the organization's force-MFA
// level.
func (s *Service) ShouldForceMFA(ctx context.Context, organizationID, userID uuid.UUID, ip, ua, country string) bool {
	level := s.Assess(ctx, organizationID, userID, ip, ua, country)
	return s.ForceMFA(ctx, organizationID, level)
}

// GetSettings returns the organization's risk settings.
func (s *Service) GetSettings(ctx context.Context, organizationID uuid.UUID) (Settings, error) {
	row, err := s.q.GetRiskSettings(ctx, organizationID)
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

// withCountrySignal sets the read-only country-header fields on st.
func withCountrySignal(st Settings) Settings {
	st.CountryHeaderConfigured = httpx.GeoCountryHeaderConfigured()
	st.CountryLastSeenAt = httpx.GeoCountryLastSeen()
	return st
}

// UpdateSettings stores the organization's risk settings, recorded as actor's with
// each setting it changed.
func (s *Service) UpdateSettings(ctx context.Context, organizationID uuid.UUID, in Settings, actor audit.Actor) (Settings, error) {
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	before := defaultSettings()
	row, err := q.LockRiskSettings(ctx, organizationID)
	switch {
	case err == nil:
		before = Settings{
			MediumThreshold: row.MediumThreshold, HighThreshold: row.HighThreshold,
			ForceMFAAtLevel: row.ForceMfaAtLevel, ImpossibleTravelEnabled: row.ImpossibleTravelEnabled,
			MinTravelHours: row.MinTravelHours, DeviceReputationEnabled: row.DeviceReputationEnabled,
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return Settings{}, err
	}
	if err := q.UpsertRiskSettings(ctx, dbgen.UpsertRiskSettingsParams{
		OrganizationID:          organizationID,
		MediumThreshold:         in.MediumThreshold,
		HighThreshold:           in.HighThreshold,
		ForceMfaAtLevel:         in.ForceMFAAtLevel,
		ImpossibleTravelEnabled: in.ImpossibleTravelEnabled,
		MinTravelHours:          in.MinTravelHours,
		DeviceReputationEnabled: in.DeviceReputationEnabled,
	}); err != nil {
		return Settings{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "risk.settings_updated", "organization", organizationID,
		map[string]any{"changes": audit.Changes(before.audited(), in.audited()), "settings": in.audited()})); err != nil {
		return Settings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Settings{}, err
	}
	return in, nil
}

// audited is the settings by name, as recorded.
func (st Settings) audited() map[string]any {
	return map[string]any{
		"medium_threshold": st.MediumThreshold, "high_threshold": st.HighThreshold,
		"force_mfa_at_level": st.ForceMFAAtLevel, "impossible_travel_enabled": st.ImpossibleTravelEnabled,
		"min_travel_hours": st.MinTravelHours, "device_reputation_enabled": st.DeviceReputationEnabled,
	}
}
