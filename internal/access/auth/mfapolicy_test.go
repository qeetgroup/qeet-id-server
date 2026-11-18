package auth

import (
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
)

func TestDecideMFARequirement(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	on := now.Add(-5 * 24 * time.Hour) // the requirement was turned on five days ago
	since := &on
	before, after := on.Add(-time.Hour), on.Add(time.Hour)

	for name, tc := range map[string]struct {
		row    dbgen.MFARequirementRow
		reason string
		grace  bool
	}{
		"optional":                       {row: dbgen.MFARequirementRow{Enforcement: "optional", JoinedAt: before}},
		"required":                       {row: dbgen.MFARequirementRow{Enforcement: "required", JoinedAt: before}, reason: mfaReasonOrganizationRequired},
		"admin_only, an administrator":   {row: dbgen.MFARequirementRow{Enforcement: "admin_only", IsAdmin: true, JoinedAt: before}, reason: mfaReasonAdminRequired},
		"admin_only, not one":            {row: dbgen.MFARequirementRow{Enforcement: "admin_only", JoinedAt: before}},
		"marked, organization optional":  {row: dbgen.MFARequirementRow{Enforcement: "optional", MfaRequired: true, JoinedAt: before}, reason: mfaReasonUserRequired},
		"marked accounts get no grace":   {row: dbgen.MFARequirementRow{Enforcement: "required", MfaRequired: true, GraceDays: 30, MfaEnforcedSince: since, JoinedAt: before}, reason: mfaReasonUserRequired},
		"grace running, existing":        {row: dbgen.MFARequirementRow{Enforcement: "required", GraceDays: 30, MfaEnforcedSince: since, JoinedAt: before}, reason: mfaReasonOrganizationRequired, grace: true},
		"grace running, admin":           {row: dbgen.MFARequirementRow{Enforcement: "admin_only", IsAdmin: true, GraceDays: 30, MfaEnforcedSince: since, JoinedAt: before}, reason: mfaReasonAdminRequired, grace: true},
		"grace running, created after":   {row: dbgen.MFARequirementRow{Enforcement: "required", GraceDays: 30, MfaEnforcedSince: since, JoinedAt: after}, reason: mfaReasonOrganizationRequired},
		"grace ended":                    {row: dbgen.MFARequirementRow{Enforcement: "required", GraceDays: 3, MfaEnforcedSince: since, JoinedAt: before}, reason: mfaReasonOrganizationRequired},
		"no grace period":                {row: dbgen.MFARequirementRow{Enforcement: "required", MfaEnforcedSince: since, JoinedAt: before}, reason: mfaReasonOrganizationRequired},
		"grace without a start recorded": {row: dbgen.MFARequirementRow{Enforcement: "required", GraceDays: 30, JoinedAt: before}, reason: mfaReasonOrganizationRequired},
	} {
		t.Run(name, func(t *testing.T) {
			got := decideMFARequirement(tc.row, now)
			if got.reason != tc.reason || (got.graceUntil != nil) != tc.grace {
				t.Fatalf("got reason %q, grace %v; want %q, grace %v", got.reason, got.graceUntil, tc.reason, tc.grace)
			}
			if tc.grace && !got.graceUntil.Equal(on.Add(time.Duration(tc.row.GraceDays)*24*time.Hour)) {
				t.Fatalf("grace until %v, want %d days after %v", got.graceUntil, tc.row.GraceDays, on)
			}
		})
	}
}

func TestMFAGate(t *testing.T) {
	totp := []LoginFactor{{Type: "totp"}}
	for name, tc := range map[string]struct {
		gate                   mfaGate
		challenged, enrollment bool
		reason                 string
	}{
		"nothing held or required": {gate: mfaGate{}, reason: mfaReasonEnrolled},
		"held, not required":       {gate: mfaGate{factors: totp}, challenged: true, reason: mfaReasonEnrolled},
		"held and required":        {gate: mfaGate{factors: totp, req: mfaRequirement{reason: mfaReasonOrganizationRequired}}, challenged: true, reason: mfaReasonOrganizationRequired},
		"required, none held":      {gate: mfaGate{req: mfaRequirement{reason: mfaReasonAdminRequired}}, challenged: true, enrollment: true, reason: mfaReasonAdminRequired},
		"marked, none held":        {gate: mfaGate{req: mfaRequirement{reason: mfaReasonUserRequired}}, challenged: true, enrollment: true, reason: mfaReasonUserRequired},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.gate.challenged() != tc.challenged || tc.gate.enrollment() != tc.enrollment || tc.gate.reason() != tc.reason {
				t.Fatalf("challenged %v, enrollment %v, reason %q; want %v, %v, %q",
					tc.gate.challenged(), tc.gate.enrollment(), tc.gate.reason(), tc.challenged, tc.enrollment, tc.reason)
			}
		})
	}
}
