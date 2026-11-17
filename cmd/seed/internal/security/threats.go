package security

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Each organization's risk and bot settings, then the attacks on it: wrong
// passwords through the auth service's own failure path, so the failed
// sign-ins, locks, throttles, security events and the locked person's alert
// are the API's own.

// riskSpec and botSpec are an organization's adaptive-risk and bot settings,
// and when its security team set them.
type riskSpec struct {
	slug  string
	after time.Duration // after the organization signed up
	risk  risk.Settings
	bot   bot.Settings
}

var riskSpecs = []riskSpec{
	{"qeet", 12 * day, risk.Settings{MediumThreshold: 0.5, HighThreshold: 0.8, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: true, MinTravelHours: 3, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.7}},
	{"northwind", 30 * day, risk.Settings{MediumThreshold: 0.4, HighThreshold: 0.7, ForceMFAAtLevel: "medium",
		ImpossibleTravelEnabled: true, MinTravelHours: 2, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, Signature: true, ScoreThreshold: 0.6}},
	{"meridian", 21 * day, risk.Settings{MediumThreshold: 0.5, HighThreshold: 0.75, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: true, MinTravelHours: 4, DeviceReputationEnabled: false},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: false, ScoreThreshold: 0.7}},
	{"lumen", 45 * day, risk.Settings{MediumThreshold: 0.55, HighThreshold: 0.85, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: false, MinTravelHours: 3, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.8}},
	{"aster", 20 * day, risk.Settings{}, bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.7}},
}

const day = 24 * time.Hour

// threatSettings stores each organization's risk and bot settings through
// their services, on the day its security team chose them.
func threatSettings(w *world.World) {
	for _, s := range riskSpecs {
		o := org(w, s.slug)
		if o == nil {
			continue
		}
		at := w.WorkHours(o.Spec.Since.Add(s.after), o.Loc)
		if at.After(w.Now) {
			at = w.Now.Add(-day)
		}
		by := first(o, at, withRole(world.RoleSecurity, world.RoleAdmin))
		w.At(at, func() {
			if s.risk.HighThreshold > 0 {
				_, err := w.Deps.Risk.Service.UpdateSettings(w.Ctx, o.ID, s.risk, by.Actor())
				w.Check(err, "risk settings for "+s.slug)
			}
			_, err := w.Deps.Bot.Service.UpdateSettings(w.Ctx, o.ID, s.bot, by.Actor())
			w.Check(err, "bot settings for "+s.slug)
		})
		if s.risk.HighThreshold > 0 {
			riskSince[s.slug] = at
		}
	}
}

// riskSince is when each organization configured adaptive risk; compliance
// evidence reads it.
var riskSince = map[string]time.Time{}

// attack is a run of wrong passwords from one attacker: several against one
// account (credential stuffing, locking it) or one each against many
// (password spraying, throttling the source).
type attack struct {
	o       *world.Org
	at      time.Time
	src     world.Device
	victims []*world.Person
	tries   int           // wrong passwords per victim
	gap     time.Duration // between attempts, in the story
	resolve time.Duration // when the SOC resolved it, after at; 0 leaves it open
}

// lockouts runs each organization's attacks through the auth service.
func lockouts(w *world.World) {
	py, curl, headless, goClient := world.Attackers[0], world.Attackers[1], world.Attackers[2], world.Attackers[3]
	var attacks []attack
	stuff := func(slug string, at time.Time, src world.Device, resolve time.Duration, keep func(*world.Person) bool) {
		o := org(w, slug)
		if o == nil {
			return
		}
		if v := victim(w, o, at, keep); v != nil {
			attacks = append(attacks, attack{o: o, at: at, src: src, victims: []*world.Person{v}, tries: 6, gap: 40 * time.Second, resolve: resolve})
		}
	}
	spray := func(slug string, at time.Time, src world.Device, resolve time.Duration) {
		o := org(w, slug)
		if o == nil {
			return
		}
		ps := people(o, at, ordinary)
		if len(ps) < w.Cfg.LoginSprayAccounts {
			return
		}
		w.Rand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		attacks = append(attacks, attack{o: o, at: at, src: src, victims: ps[:w.Cfg.LoginSprayAccounts], tries: 1, gap: 20 * time.Second, resolve: resolve})
	}
	nightIST := func(daysAgo float64, hour, minute int) time.Time {
		return localTime(w.Days(daysAgo), world.Location("Asia/Kolkata"), hour, minute)
	}
	stuff("northwind", nightIST(12, 2, 14), py, 9*time.Hour, inDept("Credit & Risk"))
	spray("northwind", nightIST(5, 1, 32), headless, 0)
	stuff("northwind", w.Now.Add(-7*time.Hour-13*time.Minute), goClient, 0, inDept("Loan Operations"))
	stuff("qeet", nightIST(20, 3, 5), curl, 5*time.Hour, inDept("Sales"))
	if o := org(w, "meridian"); o != nil {
		spray("meridian", localTime(w.Days(9), o.Loc, 4, 41), goClient, 26*time.Hour)
		stuff("meridian", localTime(w.Days(3), o.Loc, 23, 18), py, 14*time.Hour, inDept("Clinical Operations"))
	}
	if o := org(w, "lumen"); o != nil {
		stuff("lumen", w.Now.Add(-30*time.Hour), headless, 26*time.Hour, inDept("Go-to-Market"))
	}
	// People suspended for suspicious activity were locked out first.
	for _, o := range w.Orgs {
		for _, p := range o.People {
			if p.Status == world.StatusSuspended && (p.Reason == "suspicious_activity" || p.Reason == "account_compromise") &&
				p.Since.Sub(p.Joined) > 3*day {
				src := curl
				if o.Spec.Slug == "qeet" {
					src = goClient
				}
				attacks = append(attacks, attack{o: o, at: p.Since.Add(-26 * time.Hour), src: src,
					victims: []*world.Person{p}, tries: 6, gap: 35 * time.Second, resolve: 26*time.Hour - 20*time.Minute})
				compromised = append(compromised, p)
			}
		}
	}
	for _, a := range attacks {
		run(w, a)
	}
}

// compromised are the people suspended after an attack; detections names them.
var compromised []*world.Person

// victim picks an account for credential stuffing: an ordinary member present
// at t, matching keep when anyone does.
func victim(w *world.World, o *world.Org, t time.Time, keep func(*world.Person) bool) *world.Person {
	ps := people(o, t, func(p *world.Person) bool { return ordinary(p) && keep(p) })
	if len(ps) == 0 {
		ps = people(o, t, ordinary)
	}
	if len(ps) == 0 {
		return nil
	}
	return world.Pick(w, ps)
}

// wrongPasswords are what credential lists and sprays try.
var wrongPasswords = []string{"Welcome@123", "Password@2026", "Summer2026!", "Qwerty@123", "India@123", "Admin@1234", "P@ssw0rd1"}

// run plays a through the auth service at its time, then spaces the attempts
// out as the story has them and dates the locks they set, which the service
// times from the real clock.
func run(w *world.World, a attack) {
	svc := w.Deps.Auth.Service
	var times []time.Time
	w.At(a.at, func() {
		for _, v := range a.victims {
			for i := range a.tries {
				_, err := svc.Login(w.Ctx, auth.LoginInput{Email: v.Email, Password: wrongPasswords[(i+len(times))%len(wrongPasswords)],
					IP: a.src.IP, UserAgent: a.src.UserAgent})
				if err == nil || errs.As(err) == nil {
					w.Check(err, "attack "+v.Email)
					w.Check(errString("an attacker's password was accepted"), "attack "+v.Email)
				}
				times = append(times, a.at.Add(time.Duration(len(times))*a.gap))
			}
		}
	})
	spaceAttempts(w, a, times)
	lock := w.Cfg.LoginLockoutDuration
	block := w.Cfg.LoginSprayBlock
	// The counters hold the real clock; date them from the story. A lock runs
	// from the attempt that set it; a throttle from the spray's last attempt.
	for i, v := range a.victims {
		mine := times[i*a.tries : (i+1)*a.tries]
		last := mine[len(mine)-1]
		var until *time.Time
		if a.tries >= w.Cfg.LoginLockoutThreshold {
			last = lockTime(w, a)
			until = ptr(last.Add(lock))
		}
		w.Exec("date sign-in counters", `
			UPDATE auth.login_attempts_by_network SET first_failed_at = $3, last_failed_at = $4, locked_until = $5
			WHERE email = lower($1) AND network = $2`, v.Email, a.src.IP, mine[0], last, until)
		w.Exec("date account counters", `
			UPDATE auth.login_attempts SET first_failed_at = $2, last_failed_at = $3, locked_until = NULL
			WHERE email = lower($1)`, v.Email, mine[0], last)
	}
	if len(a.victims) > 1 {
		w.Exec("date source throttles", `
			UPDATE auth.login_source_throttles SET throttled_at = $2::timestamptz, throttled_until = $2::timestamptz + make_interval(secs => $3::float8)
			WHERE network = $1`, a.src.IP, lockTime(w, a), block.Seconds())
	}
	w.Exec("date lock records", `
		UPDATE audit.events SET created_at = $3::timestamptz,
		       metadata = metadata || jsonb_build_object(
		           CASE WHEN action = 'auth.account_locked' THEN 'locked_until' ELSE 'throttled_until' END,
		           to_char(($3::timestamptz + make_interval(secs => CASE WHEN action = 'auth.account_locked' THEN $4::float8 ELSE $5::float8 END))
		                   AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		WHERE organization_id = $1 AND ip = $2::inet AND action IN ('auth.account_locked', 'auth.source_throttled')
		  AND created_at BETWEEN $6 AND $7`,
		a.o.ID, a.src.IP, lockTime(w, a), lock.Seconds(), block.Seconds(), a.at.Add(-time.Minute), a.at.Add(time.Hour))
	w.Exec("date security events", `
		UPDATE auth.security_events SET created_at = $3::timestamptz,
		       metadata = metadata || CASE WHEN type = 'password_spraying'
		           THEN jsonb_build_object('throttled_until', $3::timestamptz + make_interval(secs => $5::float8))
		           ELSE jsonb_build_object('locked_until', $3::timestamptz + make_interval(secs => $4::float8)) END
		WHERE organization_id = $1 AND ip = $2::inet AND created_at BETWEEN $6 AND $7`,
		a.o.ID, a.src.IP, lockTime(w, a), lock.Seconds(), block.Seconds(), a.at.Add(-time.Minute), a.at.Add(time.Hour))
	w.Exec("date lock notifications", `
		UPDATE auth.notifications SET created_at = $3
		WHERE organization_id = $1 AND kind = 'alert' AND created_at BETWEEN $4 AND $5 AND user_id = ANY($2)`,
		a.o.ID, ids(a.victims), lockTime(w, a), a.at.Add(-time.Minute), a.at.Add(time.Hour))
	for _, t := range times {
		botAttempt(w, a.o, t, a.src.IP, a.src.UserAgent)
	}
	if a.resolve > 0 {
		resolveAttack(w, a, lockTime(w, a).Add(a.resolve))
		return
	}
	ago := fmt.Sprintf("%d hours", int(w.Now.Sub(lockTime(w, a)).Hours()+0.5))
	if d := w.Now.Sub(lockTime(w, a)); d > 48*time.Hour {
		ago = fmt.Sprintf("%d days", int(d.Hours()/24+0.5))
	}
	if len(a.victims) == 1 {
		demos = append(demos, fmt.Sprintf("Lockout: %s (%s) locked %s ago by wrong passwords from %s — open credential_stuffing "+
			"event, High risk on the person, alert in their bell", a.victims[0].Email, a.o.Spec.Name, ago, a.src.IP))
	} else {
		demos = append(demos, fmt.Sprintf("Spraying: %s throttled %s ago after failing against %d %s accounts — open password_spraying event",
			a.src.IP, ago, len(a.victims), a.o.Spec.Name))
	}
}

// lockTime is when a's lock or throttle was set: at the attempt that reached
// the threshold (the platform's, as no application is named).
func lockTime(w *world.World, a attack) time.Time {
	n := w.Cfg.LoginLockoutThreshold
	if len(a.victims) > 1 {
		n = len(a.victims)
	}
	return a.at.Add(time.Duration(n-1) * a.gap)
}

// spaceAttempts moves the failed sign-ins a recorded, which the service wrote
// moments apart, to the attempt times of the story.
func spaceAttempts(w *world.World, a attack, times []time.Time) {
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT id FROM audit.events
		WHERE organization_id = $1 AND ip = $2::inet AND action = 'auth.sign_in_failed' AND created_at BETWEEN $3 AND $4
		ORDER BY created_at, id`, a.o.ID, a.src.IP, a.at.Add(-time.Minute), a.at.Add(time.Hour))
	w.Check(err, "list an attack's failed sign-ins")
	var events []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		w.Check(rows.Scan(&id), "scan a failed sign-in")
		events = append(events, id)
	}
	rows.Close()
	for i, id := range events {
		if i < len(times) {
			w.Exec("space a failed sign-in", `UPDATE audit.events SET created_at = $2 WHERE id = $1 AND organization_id = $3`, id, times[i], a.o.ID)
		}
	}
}

// resolveAttack has the organization's security team resolve a's events at t,
// and the locked people read their alert.
func resolveAttack(w *world.World, a attack, t time.Time) {
	if t.After(w.Now) {
		return
	}
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT id FROM auth.security_events WHERE organization_id = $1 AND ip = $2::inet AND created_at BETWEEN $3 AND $4`,
		a.o.ID, a.src.IP, a.at.Add(-time.Minute), a.at.Add(time.Hour))
	w.Check(err, "list an attack's security events")
	var events []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		w.Check(rows.Scan(&id), "scan a security event")
		events = append(events, id)
	}
	rows.Close()
	by := first(a.o, t, withRole(world.RoleSecurity, world.RoleAdmin))
	w.At(t, func() {
		for _, id := range events {
			w.Check(w.Deps.Threat.Service.Resolve(w.Ctx, id, a.o.ID, by.Actor()), "resolve a security event")
		}
	})
	w.Exec("read lock alerts", `
		UPDATE auth.notifications SET read_at = $3
		WHERE organization_id = $1 AND user_id = ANY($2) AND kind = 'alert' AND read_at IS NULL AND created_at < $3`,
		a.o.ID, ids(a.victims), lockTime(w, a).Add(50*time.Minute))
}

func ids(ps []*world.Person) []uuid.UUID {
	out := make([]uuid.UUID, len(ps))
	for i, p := range ps {
		out[i] = p.ID
	}
	return out
}

type errString string

func (e errString) Error() string { return string(e) }
