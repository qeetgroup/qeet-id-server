package security

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// Detections below the lockout (bursts too slow or spread to lock, slow
// sprays) and the takeovers that got people suspended, as threat.Service.Record
// stores them, from the attackers in world.Attackers. Older ones were resolved
// by the security team; most of the last few days' are open.

// detectionRate is how many detections each organization sees in 60 days.
var detectionRate = map[string]int{"northwind": 14, "lumen": 10, "meridian": 9, "qeet": 8, "aster": 4, "kestrel": 2}

// detections records each organization's detections, and the takeover that
// preceded each suspension for suspicious activity.
func detections(w *world.World) {
	for _, o := range w.Orgs {
		n := detectionRate[o.Spec.Slug]
		for i := range n {
			// Spread over 60 days, a few in the last day.
			var t time.Time
			switch {
			case i < 2 && n >= 4:
				t = w.Now.Add(-time.Hour - time.Duration(w.Rand.Int64N(int64(22*time.Hour))))
			case i < 4 && n >= 8:
				t = w.Days(1 + 3*w.Rand.Float64())
			default:
				t = w.Days(4 + 56*w.Rand.Float64())
			}
			if t.Before(o.Spec.Since) {
				continue
			}
			detect(w, o, t)
		}
	}
	for _, p := range compromised {
		o := p.Org
		t := p.Since.Add(-35 * time.Minute)
		src := world.Abroad[w.Rand.IntN(len(world.Abroad))]
		record(w, o, t, &p.ID, "credential_stuffing", "critical",
			fmt.Sprintf("Sign-in to %s succeeded from %s (%s) after %d failed attempts across 3 networks — possible account takeover.",
				p.Email, src.IP, src.Country, 9+w.Rand.IntN(8)),
			src.IP, src.UserAgent, map[string]any{"account": p.Email, "network": src.IP, "country": src.Country, "networks": 3},
			"resolved", p.Since.Add(10*time.Minute))
	}
}

// detect records one detection in o at t.
func detect(w *world.World, o *world.Org, t time.Time) {
	src := world.Pick(w, world.Attackers)
	status, resolved := "resolved", t.Add(time.Duration(1+w.Rand.IntN(30))*time.Hour)
	if w.Now.Sub(t) < 3*day {
		// Recent: most still open, the rest closed today.
		status, resolved = "open", time.Time{}
		if w.Chance(0.4) {
			status, resolved = "resolved", w.Between(maxTime(t.Add(time.Hour), w.Now.Add(-20*time.Hour)), w.Now.Add(-20*time.Minute))
		}
	}
	if resolved.After(w.Now) || (!resolved.IsZero() && !resolved.After(t)) {
		status, resolved = "open", time.Time{}
	}
	switch r := w.Rand.Float64(); {
	case r < 0.35:
		accounts := 3 + w.Rand.IntN(5)
		record(w, o, t, nil, "credential_stuffing", "low",
			fmt.Sprintf("Failed sign-ins against %d accounts from one network within 15 minutes, below the lockout threshold.", accounts),
			src.IP, src.UserAgent, map[string]any{"network": src.IP, "distinct_accounts": accounts, "failures": accounts + w.Rand.IntN(4),
				"window_minutes": 15, "counter": "source"}, status, resolved)
	case r < 0.6:
		ps := people(o, t, ordinary)
		if len(ps) == 0 {
			return
		}
		p := world.Pick(w, ps)
		networks := 2 + w.Rand.IntN(3)
		record(w, o, t, &p.ID, "credential_stuffing", "medium",
			fmt.Sprintf("Repeated failed sign-ins for %s from %d networks within an hour.", p.Email, networks),
			src.IP, src.UserAgent, map[string]any{"account": p.Email, "network": src.IP, "networks": networks,
				"failures": networks*2 + w.Rand.IntN(3), "window_minutes": 60, "counter": "account"}, status, resolved)
	case r < 0.85:
		accounts := 8 + w.Rand.IntN(18)
		record(w, o, t, nil, "password_spraying", "medium",
			fmt.Sprintf("One network tried common passwords against %d accounts in 15 minutes.", accounts),
			src.IP, src.UserAgent, map[string]any{"network": src.IP, "distinct_accounts": accounts, "window_minutes": 15,
				"counter": "source"}, status, resolved)
	default:
		accounts := 12 + w.Rand.IntN(30)
		hours := 6 + w.Rand.IntN(18)
		record(w, o, t, nil, "password_spraying", "low",
			fmt.Sprintf("Slow password spray: %d accounts over %d hours from one network, too slow to throttle.", accounts, hours),
			src.IP, src.UserAgent, map[string]any{"network": src.IP, "distinct_accounts": accounts, "window_minutes": hours * 60,
				"counter": "source"}, status, resolved)
	}
}

// record writes one security event as threat.Service.Record stores it.
func record(w *world.World, o *world.Org, t time.Time, user *uuid.UUID, typ, severity, detail, ip, ua string,
	meta map[string]any, status string, resolved time.Time) {
	m, err := json.Marshal(meta)
	w.Check(err, "encode detection metadata")
	var resolvedAt *time.Time
	if !resolved.IsZero() {
		resolvedAt = &resolved
	}
	w.Exec("record a detection", `
		INSERT INTO auth.security_events (organization_id, user_id, type, severity, detail, status, ip, user_agent, metadata, created_at, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::inet, NULLIF($8, ''), $9, $10, $11)`,
		o.ID, user, typ, severity, detail, status, ip, ua, m, t, resolvedAt)
}
