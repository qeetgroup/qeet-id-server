package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
)

// An audit anomaly is written as the audited action plus the anomaly the API's
// sweep would raise on it — a new action, an unusual hour, a new address —
// scored with the sweep's weights (0.5, up to 0.3, 0.2). The last week's are
// open; older ones were resolved by the security team.

// anomalyPlan is an organization's anomaly settings and how many anomalies it
// has seen in 60 days.
type anomalyPlan struct {
	slug     string
	settings anomaly.Settings
	count    int
}

var anomalyPlans = []anomalyPlan{
	{"northwind", anomaly.Settings{Enabled: true, ScoreThreshold: 0.55, MinBaselineEvents: 25}, 8},
	{"qeet", anomaly.Settings{Enabled: true, ScoreThreshold: 0.6, MinBaselineEvents: 20}, 6},
	{"lumen", anomaly.Settings{Enabled: true, ScoreThreshold: 0.6, MinBaselineEvents: 20}, 6},
	{"meridian", anomaly.Settings{Enabled: true, ScoreThreshold: 0.65, MinBaselineEvents: 30}, 5},
	{"aster", anomaly.Settings{Enabled: true, ScoreThreshold: 0.6, MinBaselineEvents: 20}, 2},
	{"kestrel", anomaly.Settings{Enabled: false, ScoreThreshold: 0.6, MinBaselineEvents: 20}, 0},
}

// auditAnomalies stores each organization's anomaly settings and the anomalies
// flagged on its people.
func auditAnomalies(w *world.World) {
	for _, plan := range anomalyPlans {
		o := org(w, plan.slug)
		if o == nil {
			continue
		}
		at := w.WorkHours(o.Spec.Since.Add(25*day), o.Loc)
		if at.After(w.Now) {
			at = w.Now.Add(-day)
		}
		w.At(at, func() {
			_, err := w.Deps.AuditAnomaly.Service.UpdateSettings(w.Ctx, o.ID, plan.settings)
			w.Check(err, "anomaly settings for "+plan.slug)
		})
		open := 0
		for i := range plan.count {
			t := w.Days(1 + 59*w.Rand.Float64())
			if i < plan.count/3+1 {
				t = w.Days(0.2 + 6*w.Rand.Float64())
			}
			if t.Before(at) {
				continue
			}
			if flag(w, o, t, plan.settings.ScoreThreshold) {
				open++
			}
		}
		if plan.count > 0 {
			fact(o, "%d open audit anomalies", open)
		}
	}
}

// flag writes one anomalous action in o around t and the anomaly raised on it,
// reporting whether it is still open.
func flag(w *world.World, o *world.Org, t time.Time, threshold float64) bool {
	e := audit.Event{OrganizationID: &o.ID}
	builders := w.Rand.Perm(5)
	var p *world.Person
	for _, b := range builders {
		if p = anomalousAction(w, o, t, b, &e); p != nil {
			break
		}
	}
	if p == nil {
		return false
	}
	night := w.Chance(0.6)
	when := w.WorkHours(t, p.Loc)
	if night {
		when = localTime(t, p.Loc, 1+w.Rand.IntN(3), w.Rand.IntN(60))
	}
	if when.After(w.Now) {
		when = w.Now.Add(-2 * time.Hour)
	}
	ip := strangeAddress(w, p)
	e.ActorUserID, e.IP, e.UserAgent = &p.ID, ip, p.Device.UserAgent
	reasons := []string{"new_action_type"}

	// The sweep's score: a never-taken action, the hour's novelty, a new address.
	score := 0.5
	if night {
		novelty := 0.6 + 0.4*w.Rand.Float64()
		score += 0.3 * novelty
		reasons = append(reasons, "unusual_hour")
	} else {
		score += 0.3 * 0.4 * w.Rand.Float64()
	}
	if ip != p.Device.IP {
		score += 0.2
		reasons = append(reasons, "new_ip")
	}
	score = min(score, 1)
	if score < threshold {
		return false
	}
	eventID := w.Audit(when, e)

	flagged := when.Add(time.Duration(20+w.Rand.IntN(70)) * time.Second)
	status := "open"
	var resolvedAt *time.Time
	var resolvedBy *uuid.UUID
	if w.Now.Sub(when) > 7*day || w.Chance(0.25) {
		if r := resolver(o, flagged); r != nil && r != p {
			done := w.WorkHours(flagged.Add(time.Duration(2+w.Rand.IntN(40))*time.Hour), r.Loc)
			if done.After(flagged) && done.Before(w.Now) {
				status, resolvedAt, resolvedBy = "resolved", &done, &r.ID
			}
		}
	}
	w.Exec("flag an audit anomaly", `
		INSERT INTO audit.anomalies (organization_id, event_id, actor_user_id, score, reasons, status, resolved_at, resolved_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		o.ID, eventID, p.ID, float64(int(score*1000))/1000, reasons, status, resolvedAt, resolvedBy, flagged)
	return status == "open"
}

// anomalousAction fills e with the kind-th sort of flagged action — revealing
// a secret, rotating an application's secret, changing the security policy or
// one's password, signing out other sessions — and returns who took it around
// t, or nil when o has nobody (or nothing) for it yet.
func anomalousAction(w *world.World, o *world.Org, t time.Time, kind int, e *audit.Event) *world.Person {
	pick := func(keep func(*world.Person) bool) *world.Person {
		ps := people(o, t, func(p *world.Person) bool { return ordinary(p) && keep(p) })
		if len(ps) == 0 {
			return nil
		}
		return world.Pick(w, ps)
	}
	builders := withRole(world.RoleDeveloper, world.RoleSecurity)
	admins := withRole(world.RoleAdmin, world.RoleITAdmin, world.RoleSecurity)
	anyone := func(*world.Person) bool { return true }
	switch kind {
	case 0:
		id, name, ok := organizationRow(w, o, `SELECT id, name FROM organization.secrets WHERE organization_id = $1 AND created_at < $2 ORDER BY created_at LIMIT 1`, t)
		p := pick(builders)
		if !ok || p == nil {
			return nil
		}
		e.Action, e.ResourceType, e.ResourceID, e.Metadata = "secret.revealed", "secret", &id, map[string]any{"name": name}
		return p
	case 1:
		id, clientID, ok := organizationRow(w, o, `SELECT id, client_id FROM auth.oidc_clients
			WHERE organization_id = $1 AND type = 'confidential' AND created_at < $2 ORDER BY created_at LIMIT 1`, t)
		p := pick(builders)
		if !ok || p == nil {
			return nil
		}
		e.Action, e.ResourceType, e.ResourceID, e.Metadata = "oidc.client_secret_rotated", "oidc_client", &id, map[string]any{"client_id": clientID}
		return p
	case 2:
		mfa, ok := policyMFA(w, o)
		p := pick(admins)
		if !ok || p == nil {
			return nil
		}
		e.Action, e.ResourceType, e.ResourceID, e.Metadata = "security_policy.updated", "tenant", &o.ID, map[string]any{"mfa_enforcement": mfa}
		return p
	case 3:
		p := pick(anyone)
		if p == nil {
			return nil
		}
		e.Action, e.ResourceType, e.ResourceID = "auth.password_changed", "user", &p.ID
		e.Metadata = map[string]any{"revoked_sessions": 1 + w.Rand.IntN(3), "revoked_login_sessions": w.Rand.IntN(2)}
		return p
	default:
		p := pick(anyone)
		if p == nil {
			return nil
		}
		e.Action, e.ResourceType, e.ResourceID = "auth.other_sessions_revoked", "user", &p.ID
		e.Metadata = map[string]any{"revoked": 1 + w.Rand.IntN(4)}
		return p
	}
}

// organizationRow reads one (id, name) row of o's that existed by t with sql, which
// takes the organization and t; ok is false when there is none.
func organizationRow(w *world.World, o *world.Org, sql string, t time.Time) (uuid.UUID, string, bool) {
	var id uuid.UUID
	var name string
	err := w.Admin.QueryRow(w.Ctx, sql, o.ID, t).Scan(&id, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, "", false
	}
	w.Check(err, "read a resource of "+o.Spec.Slug)
	return id, name, true
}

// strangeAddress is an address p is unlikely to have used before: an airport
// or hotel abroad, or a different line at home. Some anomalies come from p's
// usual address.
func strangeAddress(w *world.World, p *world.Person) string {
	switch r := w.Rand.Float64(); {
	case r < 0.3:
		return p.Device.IP
	case r < 0.6:
		return world.Pick(w, world.Abroad).IP
	default:
		c := officeOf(p)
		ip := fmt.Sprintf("%s%d", c.Block, c.Lo+w.Rand.IntN(c.Hi-c.Lo+1))
		if ip == p.Device.IP {
			return world.Pick(w, world.Abroad).IP
		}
		return ip
	}
}

// resolver is who reviews o's anomalies at t: a security analyst, else an
// administrator.
func resolver(o *world.Org, t time.Time) *world.Person {
	if ps := people(o, t, withRole(world.RoleSecurity)); len(ps) > 0 {
		return ps[0]
	}
	if ps := people(o, t, withRole(world.RoleAdmin)); len(ps) > 0 {
		return ps[0]
	}
	return nil
}

// policyMFA returns o's MFA enforcement, if it has a security policy yet.
func policyMFA(w *world.World, o *world.Org) (string, bool) {
	var mfa string
	err := w.Admin.QueryRow(w.Ctx, `SELECT mfa_enforcement FROM organization.security_policies WHERE organization_id = $1`, o.ID).Scan(&mfa)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false
	}
	w.Check(err, "read the security policy of "+o.Spec.Slug)
	return mfa, true
}
