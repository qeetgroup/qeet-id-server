//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
)

const macUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"

// TestRiskAssess_ImpossibleTravelAndDeviceReputation drives the two new
// adaptive-MFA signals end to end against a real DB-backed history: a first
// login records the user's device+country (and, since every device is new to
// a user exactly once, contributes the new-device bump — but not enough
// alone to leave Low); a second login from a different country shortly after
// crosses the impossible-travel threshold; a third from the same
// country+device as the second is unremarkable again.
func TestRiskAssess_ImpossibleTravelAndDeviceReputation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("risk"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := risk.NewService(testPool)
	if _, err := svc.UpdateSettings(ctx, tenantID, risk.Settings{
		MediumThreshold: 0.50, HighThreshold: 0.80, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: true, MinTravelHours: 3,
		DeviceReputationEnabled: true,
	}); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	// First login: no history yet. The device is new (score 0.25 from the
	// bump) but there's no prior country to compare against, so travel can't
	// fire. 0.25 < medium(0.50) => Low.
	first := svc.Assess(ctx, tenantID, userID, "203.0.113.1", macUA, "US")
	if first != risk.Low {
		t.Fatalf("first login level = %v, want Low", first)
	}

	// Second login: same device (no longer new) but a different country
	// immediately after — well under MinTravelHours. Pure impossible-travel
	// signal: 0 (bot) + 0.5 (travel) = 0.5 >= medium(0.50) => Medium.
	second := svc.Assess(ctx, tenantID, userID, "203.0.113.2", macUA, "FR")
	if second != risk.Medium {
		t.Fatalf("second login (new country, same device) level = %v, want Medium", second)
	}

	// Third login: same country as the second, same device — both signals
	// are now unremarkable.
	third := svc.Assess(ctx, tenantID, userID, "203.0.113.2", macUA, "FR")
	if third != risk.Low {
		t.Fatalf("third login (familiar country+device) level = %v, want Low", third)
	}
}

// TestRiskAssess_SignalsOffByDefault confirms the two new signals don't
// affect scoring unless a tenant explicitly opts in — an untouched
// auth.risk_settings row (no UpdateSettings call at all) must behave
// exactly as the pre-existing bot-score-only engine did.
func TestRiskAssess_SignalsOffByDefault(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("risk-off"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := risk.NewService(testPool)

	svc.Assess(ctx, tenantID, userID, "203.0.113.1", macUA, "US")
	// A different country immediately after would trip impossible-travel if
	// enabled; with default settings (both signals off) it must not.
	level := svc.Assess(ctx, tenantID, userID, "203.0.113.2", macUA, "FR")
	if level != risk.Low {
		t.Fatalf("level with signals off = %v, want Low", level)
	}
}

// TestRiskSettings_RoundTrip exercises the extended Settings shape through
// Get/UpdateSettings.
func TestRiskSettings_RoundTrip(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("risk-settings"))
	svc := risk.NewService(testPool)

	in := risk.Settings{
		MediumThreshold: 0.4, HighThreshold: 0.9, ForceMFAAtLevel: "medium",
		ImpossibleTravelEnabled: true, MinTravelHours: 6,
		DeviceReputationEnabled: true,
	}
	if _, err := svc.UpdateSettings(ctx, tenantID, in); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := svc.GetSettings(ctx, tenantID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != in {
		t.Fatalf("round-tripped settings = %+v, want %+v", got, in)
	}
}
