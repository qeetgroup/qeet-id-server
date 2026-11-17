package security

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
)

// Bot verdicts are what the sign-in handler records for a suspicious client:
// the score bot.Score gives its user agent and the verdict the organization's
// threshold makes of it. The bots screen counts only the last 24 hours, so a
// realistic share falls there.

// scraper is a client that tries sign-in from outside any customer's network.
type scraper struct{ ip, ua string }

var scrapers = []scraper{
	{"203.0.113.244", ""},
	{"203.0.113.245", "okhttp/4.12.0"},
	{"192.0.2.236", "Wget/1.21.4"},
	{"203.0.113.233", "Scrapy/2.11.2 (+https://scrapy.org)"},
	{"198.51.100.249", "python-urllib3/2.2.3"},
	{"198.51.100.247", "axios/1.7.9"},
}

// botRate is each organization's daily suspicious sign-in attempts.
var botRate = map[string]float64{"northwind": 6, "lumen": 5, "meridian": 4, "qeet": 3, "aster": 2, "kestrel": 1}

// botTraffic records each organization's suspicious sign-in attempts over the
// last 30 days: scripts and scrapers working through its people's addresses,
// and its own people's odd clients — a developer's Postman, an old Outlook, an
// Android app's built-in browser.
func botTraffic(w *world.World) {
	for _, o := range w.Orgs {
		rate := botRate[o.Spec.Slug]
		if rate == 0 {
			continue
		}
		n := 0
		for d := 30; d >= 0; d-- {
			count := rate * (0.5 + w.Rand.Float64())
			if d == 0 {
				count *= 2.5 // today's tiles
			}
			for range int(count + 0.5) {
				t := w.Days(float64(d) + w.Rand.Float64())
				if d == 0 {
					t = w.Now.Add(-time.Duration(w.Rand.Int64N(int64(23 * time.Hour))))
				}
				if t.After(w.Now) || t.Before(o.Spec.Since) {
					continue
				}
				ps := people(o, t, nil)
				if len(ps) == 0 {
					continue
				}
				p := world.Pick(w, ps)
				switch r := w.Rand.Float64(); {
				case r < 0.5:
					s := world.Pick(w, world.Attackers)
					botAttempt(w, o, t, s.IP, s.UserAgent)
				case r < 0.75:
					s := world.Pick(w, scrapers)
					botAttempt(w, o, t, s.ip, s.ua)
				case r < 0.83 && (p.Role == world.RoleDeveloper || p.Department == "Engineering"):
					botAttempt(w, o, t, p.Device.IP, "PostmanRuntime/7.43.0")
				case r < 0.9:
					botAttempt(w, o, t, officeOf(p).Office, "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.18129; Pro)")
				default:
					botAttempt(w, o, t, p.Mobile.IP, "Dalvik/2.1.0 (Linux; U; Android 15; "+world.Pick(w, []string{"SM-A556E", "CPH2581", "2312DRA50I"})+" Build/AP3A.240905.015)")
				}
				n++
			}
		}
		fact(o, "%d bot verdicts in 30 days", n)
	}
}

// botAttempt records the verdict the sign-in handler reaches for a client
// with user agent ua trying to sign in to o at t, as bot.Service.Evaluate
// does: nothing for a clean browser, else challenged or blocked by the
// organization's threshold at the time.
func botAttempt(w *world.World, o *world.Org, t time.Time, ip, ua string) {
	score := bot.Score(ua)
	if score < 0.30 {
		return
	}
	threshold := bot.DefaultSettings().ScoreThreshold
	for _, s := range riskSpecs {
		if s.slug == o.Spec.Slug && !t.Before(o.Spec.Since.Add(s.after)) {
			threshold = s.bot.ScoreThreshold
		}
	}
	verdict := "allowed"
	switch {
	case score >= threshold:
		verdict = "blocked"
	case score >= 0.5:
		verdict = "challenged"
	}
	insertBotEvent(w, o, t, ip, ua, score, verdict)
}

func insertBotEvent(w *world.World, o *world.Org, t time.Time, ip, ua string, score float64, verdict string) {
	w.Exec("record a bot verdict", `
		INSERT INTO auth.bot_events (organization_id, ip, user_agent, score, verdict, created_at)
		VALUES ($1, NULLIF($2, '')::inet, $3, $4, $5, $6)`, o.ID, ip, ua, score, verdict, t)
}
