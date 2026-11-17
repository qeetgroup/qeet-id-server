// Package security seeds people's second factors, passkeys and devices, and
// each organization's threat posture: IP rules, risk and bot settings, bot
// verdicts, security events, audit anomalies, compliance evidence and
// lockouts.
package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// Seed enrols factors and records every organization's security history.
func Seed(w *world.World) {
	enrolFactors(w)
	rememberDevices(w)
	addressRules(w)
	threatSettings(w)
	lockouts(w)
	detections(w)
	botTraffic(w)
	auditAnomalies(w)
	controlOwners(w)
	recordAudits(w)
	evidence(w)
	verificationRuns(w)
	statusIncidents(w)
	summarise(w)
}

// securitySection is the summary section on each organization's security
// screens.
const securitySection = "Security (Threats, IP allowlist, Audit intelligence, Compliance)"

// facts are what each organization's security screens show, for the summary.
var facts = map[*world.Org][]string{}

// fact notes something o's security screens show.
func fact(o *world.Org, format string, args ...any) {
	facts[o] = append(facts[o], fmt.Sprintf(format, args...))
}

// summarise prints one line per organization with security data, then the
// demonstrations to try.
func summarise(w *world.World) {
	for _, o := range w.Orgs {
		var open, today int
		w.Check(w.Admin.QueryRow(w.Ctx, `
			SELECT count(*) FILTER (WHERE resolved_at IS NULL), count(*) FILTER (WHERE created_at > now() - interval '24 hours')
			FROM auth.security_events WHERE organization_id = $1`, o.ID).Scan(&open, &today), "count security events")
		if open+today > 0 {
			facts[o] = append([]string{fmt.Sprintf("%d unresolved security events (%d in 24 h)", open, today)}, facts[o]...)
		}
		if len(facts[o]) > 0 {
			w.Note(securitySection, "%-26s %s", o.Spec.Name, strings.Join(facts[o], " · "))
		}
	}
	for _, d := range demos {
		w.Note(securitySection, "%s", d)
	}
}

// demos are the security behaviours a tester can try, for the summary.
var demos []string

// org returns the seeded organization with slug, or nil.
func org(w *world.World, slug string) *world.Org {
	for _, o := range w.Orgs {
		if o.Spec.Slug == slug {
			return o
		}
	}
	return nil
}

// presentAt reports whether p was a member who could sign in at t: joined,
// verified, and not yet suspended or deleted.
func presentAt(p *world.Person, t time.Time) bool {
	if p.ID == uuid.Nil || p.Unverified || p.Joined.After(t) {
		return false
	}
	return p.Status == world.StatusActive || p.Since.After(t)
}

// people returns o's people present at t that match keep (nil keeps all).
func people(o *world.Org, t time.Time, keep func(*world.Person) bool) []*world.Person {
	var out []*world.Person
	for _, p := range o.People {
		if presentAt(p, t) && (keep == nil || keep(p)) {
			out = append(out, p)
		}
	}
	return out
}

// first returns the first of o's people present at t that match keep, falling
// back to the owner.
func first(o *world.Org, t time.Time, keep func(*world.Person) bool) *world.Person {
	if ps := people(o, t, keep); len(ps) > 0 {
		return ps[0]
	}
	return o.Owner
}

// inDept matches people in department dept holding one of roles (any role
// when none are given).
func inDept(dept string, roles ...string) func(*world.Person) bool {
	return func(p *world.Person) bool {
		if p.Department != dept {
			return false
		}
		if len(roles) == 0 {
			return true
		}
		for _, r := range roles {
			if p.Role == r {
				return true
			}
		}
		return false
	}
}

// withRole matches people holding one of roles.
func withRole(roles ...string) func(*world.Person) bool {
	return func(p *world.Person) bool {
		for _, r := range roles {
			if p.Role == r {
				return true
			}
		}
		return false
	}
}

// ordinary matches people who are not test accounts, so seeded incidents never
// touch an account a tester signs in with.
func ordinary(p *world.Person) bool { return p.Login == "" }

// localTime is the given wall-clock time on t's date in loc.
func localTime(t time.Time, loc *time.Location, hour, minute int) time.Time {
	l := t.In(loc)
	return time.Date(l.Year(), l.Month(), l.Day(), hour, minute, 0, 0, loc).UTC()
}

func ptr[T any](v T) *T { return &v }
