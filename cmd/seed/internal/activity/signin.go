package activity

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// holidays are the public holidays in the history window, by country, when
// offices are shut.
var holidays = map[string][]string{
	"IN": {"2026-08-15", "2026-09-14", "2026-10-02", "2026-10-20"},
	"US": {"2026-09-07"},
	"GB": {"2026-08-31"},
	"DE": {"2026-10-03"},
}

// offices are the office cities by name, for the office network's address.
var offices = func() map[string]world.City {
	m := map[string]world.City{}
	for _, l := range []world.Locale{world.India, world.UnitedStates, world.Germany, world.Britain, world.Norway, world.Europe} {
		for _, c := range l.Cities {
			m[c.Name] = c
		}
	}
	return m
}()

// workingDay reports whether t's local day is a working day where p lives.
func workingDay(p *world.Person, t time.Time) bool {
	l := t.In(p.Loc)
	if l.Weekday() == time.Saturday || l.Weekday() == time.Sunday {
		return false
	}
	day := l.Format("2006-01-02")
	for _, h := range holidays[p.Country] {
		if h == day {
			return false
		}
	}
	return true
}

// shiftWorker reports whether p works shifts, weekends included: ward staff,
// the warehouse floor and freight dispatch.
func shiftWorker(p *world.Person) bool {
	return p.Department == "Clinical Operations" || p.Department == "Warehouse" || p.Team == "Dispatch"
}

// automation reports whether p is a test-automation account, which signs in
// every morning for the regression run.
func automation(p *world.Person) bool { return p.Title == "Test account" }

// offDayRate is the share of a working day's sign-ins p makes on a day off:
// Indian offices often work Saturdays, and software people check in at
// weekends.
func offDayRate(o *world.Org, p *world.Person, t time.Time) float64 {
	wd := t.In(p.Loc).Weekday()
	switch {
	case o.Spec.Country == "IN" && wd == time.Saturday:
		return 0.35
	case strings.HasPrefix(o.Spec.Industry, "Software"):
		return 0.35
	case wd == time.Sunday:
		return 0.08
	}
	return 0.12
}

// signIns generates p's sign-ins to their own organization over the history
// window, ending when they left.
func (h *history) signIns(o *world.Org, p *world.Person) {
	w := h.w
	if p.Unverified || p.ID == uuid.Nil {
		return
	}
	from := maxTime(p.Joined.Add(jitter(w, 4, 40)), w.Days(historyDays))
	to := w.Now.Add(-90 * time.Second)
	if p.Status != world.StatusActive {
		to = p.Since
	}
	if !to.After(from) {
		return
	}
	// About half the long-standing people took a week or so off.
	var leaveFrom, leaveTo time.Time
	if p.Joined.Before(w.Days(60)) && p.Login == "" && w.Chance(0.55) {
		leaveFrom = w.Between(w.Days(85), w.Days(12))
		leaveTo = leaveFrom.Add(time.Duration(5+w.Rand.IntN(6)) * 24 * time.Hour)
	}
	dayShift := w.Chance(0.6)

	f := from.In(p.Loc)
	for day := time.Date(f.Year(), f.Month(), f.Day(), 0, 0, 0, 0, p.Loc); !day.After(to); day = day.AddDate(0, 0, 1) {
		noon := day.Add(12 * time.Hour)
		working := workingDay(p, noon)
		var mins []int
		onLeave := !leaveFrom.IsZero() && noon.After(leaveFrom) && noon.Before(leaveTo)
		switch {
		case automation(p):
			mins = []int{390 + w.Rand.IntN(20)}
		case shiftWorker(p):
			// Five shifts a week, any day, each starting at a shared workstation.
			n := poisson(w, 0.05)
			if !onLeave && w.Chance(5.0/7) {
				n = max(1, min(poisson(w, p.Activity), 4))
			}
			mins = dayTimes(w, p, n, true, dayShift)
		default:
			rate := p.Activity
			if !working {
				rate *= offDayRate(o, p, noon)
			}
			if onLeave {
				rate *= 0.05
			}
			n := min(poisson(w, rate), 5)
			if n == 0 && p.Login != "" && working {
				n = 1
			}
			mins = dayTimes(w, p, n, working, dayShift)
		}
		for i, m := range mins {
			t := localTime(w, day, p.Loc, m)
			if t.Before(from) || t.After(to) {
				continue
			}
			kind := "desktop"
			switch {
			case automation(p):
			case i == 0 && (working || shiftWorker(p)):
				if w.Chance(0.1) {
					kind = "mobile"
				}
			case !working:
				if w.Chance(0.7) {
					kind = "mobile"
				}
			case w.Chance(0.55):
				kind = "mobile"
			}
			h.newSession(o, p, t, kind, h.duration(p, t, kind, i == 0 && working))
		}
	}
}

// dayTimes returns the minutes after local midnight of n sign-ins on one day,
// earliest first: the first at the start of the working day or shift, the
// rest through the afternoon and evening.
func dayTimes(w *world.World, p *world.Person, n int, working, dayShift bool) []int {
	if n == 0 {
		return nil
	}
	out := make([]int, 0, n)
	switch {
	case shiftWorker(p) && dayShift:
		out = append(out, 380+w.Rand.IntN(60))
	case shiftWorker(p):
		out = append(out, 1100+w.Rand.IntN(60))
	case working:
		out = append(out, 510+w.Rand.IntN(120))
	default:
		out = append(out, 600+w.Rand.IntN(600))
	}
	for len(out) < n {
		m := 660 + w.Rand.IntN(630)
		if m > out[0] {
			out = append(out, m)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 1 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// duration is how long a session signed in at t stays in use: the working
// day or shift for the first desktop sign-in, minutes on a phone.
func (h *history) duration(p *world.Person, t time.Time, kind string, firstOfDay bool) time.Duration {
	w := h.w
	switch {
	case automation(p):
		return jitter(w, 6, 18)
	case kind != "desktop":
		return jitter(w, 2, 40)
	case firstOfDay && shiftWorker(p):
		return jitter(w, 8*60, 12*60)
	case firstOfDay:
		l := t.In(p.Loc)
		end := time.Date(l.Year(), l.Month(), l.Day(), 16, 30, 0, 0, p.Loc).Add(jitter(w, 0, 180))
		if d := end.Sub(t); d > time.Hour {
			return d
		}
		return jitter(w, 60, 240)
	}
	return jitter(w, 20, 180)
}

// newSession adds a session p opened in o at t, used for dur, and decides
// how it ended.
func (h *history) newSession(o *world.Org, p *world.Person, t time.Time, kind string, dur time.Duration) *session {
	w := h.w
	pol := h.policies[o.ID]
	first := h.firstFactor(o, p, t, kind)
	method, factor := h.complete(o, p, t, first)
	s := &session{
		id: uuid.New(), p: p, org: o, dev: h.device(o, p, t, kind), method: method, first: first, factor: factor,
		created: t, lastSeen: t.Add(dur), expires: t.Add(pol.maxAge), idle: pol.idle,
	}
	if s.lastSeen.After(s.expires) {
		s.lastSeen = s.expires
	}
	switch {
	case s.lastSeen.After(w.Now.Add(-time.Minute)):
		// Still in use.
		s.lastSeen = maxTime(t.Add(time.Minute), w.Now.Add(-jitter(w, 1, 12)))
	case kind == "mobile" && w.Chance(0.1),
		kind == "desktop" && w.Chance(0.4),
		automation(p):
		s.ended = s.lastSeen.Add(time.Duration(3+w.Rand.IntN(90)) * time.Second)
		if s.ended.After(w.Now) {
			s.ended = time.Time{}
		}
	}
	if (first == "password" || first == "ldap") && w.Chance(0.05) {
		s.typos = 1
		if w.Chance(0.15) {
			s.typos = 2
		}
	}
	h.add(s)
	return s
}

// firstFactor picks how p signs in to o at t: the organization's single
// sign-on for the staff it provisions, otherwise a mix of what it allows and
// what p has set up. Test accounts mostly use their password, as testers do.
func (h *history) firstFactor(o *world.Org, p *world.Person, t time.Time, kind string) string {
	w := h.w
	f := o.Spec.Features
	if automation(p) {
		return "password"
	}
	if f.LDAP && p.Provisioned == "ldap" {
		if h.passkeyOK(o, p, t) && w.Chance(0.1) {
			return "passkey"
		}
		return "ldap"
	}
	type option struct {
		method string
		weight float64
	}
	opts := []option{{"password", 1}}
	if f.SSO != "" && f.SSOStatus == "active" && o.Has("pro") {
		weight := 3.0
		if p.Provisioned == "scim" {
			weight, opts[0].weight = 12, 0.3
		}
		opts = append(opts, option{"saml", weight})
	}
	if len(f.Social) > 0 && h.hasSocial(o, p) {
		opts = append(opts, option{"social", 1.6})
	}
	if f.MagicLink && h.magicOK(p, t) {
		opts = append(opts, option{"magic_link", 0.6})
	}
	if h.passkeyOK(o, p, t) {
		weight := 1.2
		if kind != "desktop" {
			weight = 2.4
		}
		opts = append(opts, option{"passkey", weight})
	}
	if p.Login != "" || p == o.Owner {
		opts[0].weight += 5
	}
	total := 0.0
	for _, o := range opts {
		total += o.weight
	}
	r := w.Rand.Float64() * total
	for _, o := range opts {
		if r < o.weight {
			return o.method
		}
		r -= o.weight
	}
	return "password"
}

// passkeyOK reports whether p had a passkey to sign in with at t.
func (h *history) passkeyOK(o *world.Org, p *world.Person, t time.Time) bool {
	return o.Spec.Features.Passkeys && p.HasFactor("passkey") && !t.Before(p.MFASince)
}

// magicOK reports whether sign-in links still reached p at t.
func (h *history) magicOK(p *world.Person, t time.Time) bool {
	v, ok := h.noMagic[p]
	return !ok || !v.contains(t)
}

// hasSocial reports whether p signs in with a social account: those linked
// in the database, or about two in five where the seed linked none.
func (h *history) hasSocial(o *world.Org, p *world.Person) bool {
	if h.socialSeeded[o.ID] {
		return h.social[p.ID]
	}
	return int(p.ID[15])%5 < 2
}

// hasMFA reports whether p had a second factor at t.
func hasMFA(p *world.Person, t time.Time) bool {
	return len(p.MFA) > 0 && !t.Before(p.MFASince)
}

// mfaRequired reports whether o requires p to use a second factor.
func mfaRequired(o *world.Org, p *world.Person) bool {
	switch o.Spec.Features.MFA {
	case "required":
		return true
	case "admin_only":
		return isAdmin(p)
	}
	return false
}

func isAdmin(p *world.Person) bool {
	switch p.Role {
	case world.RoleOwner, world.RoleAdmin, world.RoleITAdmin, world.RoleSecurity:
		return true
	}
	return false
}

// complete is the method a sign-in with first factor first records, and the
// second factor its session carries: "_mfa" when a second factor was met,
// the first factor alone when enrolment was put off within a grace period.
func (h *history) complete(o *world.Org, p *world.Person, t time.Time, first string) (method, factor string) {
	switch first {
	case "passkey":
		return "passkey", "passkey"
	case "password", "magic_link", "social", "ldap":
		if hasMFA(p, t) || (mfaRequired(o, p) && o.Spec.Features.MFAGrace == 0) {
			return first + "_mfa", "mfa"
		}
	}
	return first, ""
}

// device is the device p signs in from at t: their computer or phone, on the
// office network on most working days, or wherever they travelled. Where only
// the office network may sign in, it is always the headquarters' network.
func (h *history) device(o *world.Org, p *world.Person, t time.Time, kind string) world.Device {
	w := h.w
	d := p.Device
	if kind != "desktop" {
		d = p.Mobile
	}
	if hq, ok := offices[o.Spec.City]; ok && o.Spec.Features.IPAllowlist {
		d.IP, d.City, d.Country = hq.Office, hq.Name, o.Spec.Country
		return d
	}
	if tr, ok := h.trips[p]; ok && !t.Before(tr.from) && t.Before(tr.to) {
		d.IP, d.City, d.Country = tr.dev.IP, tr.dev.City, tr.dev.Country
		return d
	}
	office, ok := offices[p.City]
	if !ok || p.Country != o.Spec.Country {
		return d
	}
	share := 0.6
	if kind != "desktop" {
		share = 0.3
	}
	if (workingDay(p, t) && !shiftWorker(p) && w.Chance(share)) || (shiftWorker(p) && kind == "desktop") {
		d.IP = office.Office
	}
	return d
}

// guestSwitches opens sessions in the organizations p belongs to as a
// guest: on some working days p switches from their own organization's
// session to the other, which replaces it.
func (h *history) guestSwitches(p *world.Person, o *world.Org, since time.Time, rate float64) {
	w := h.w
	if p.Status != world.StatusActive {
		return
	}
	for _, s := range h.byPerson(p) {
		if s.org != p.Org || s.first == "tenant_switch" || s.created.Before(since) || s.superseded != uuid.Nil ||
			s.dev.Kind != "desktop" || !workingDay(p, s.created) || !w.Chance(rate) {
			continue
		}
		at := s.created.Add(jitter(w, 2, 25))
		if !s.liveAt(at) || at.After(w.Now.Add(-time.Minute)) {
			continue
		}
		g := &session{
			id: uuid.New(), p: p, org: o, dev: s.dev, method: "tenant_switch", first: "tenant_switch", factor: s.factor,
			created: at, lastSeen: maxTime(s.lastSeen, at.Add(jitter(w, 5, 40))), ended: s.ended, expires: s.expires,
			idle: h.policies[o.ID].idle, previous: s,
		}
		if g.lastSeen.After(w.Now) {
			g.lastSeen = w.Now.Add(-jitter(w, 1, 10))
		}
		if !g.ended.IsZero() && g.ended.Before(g.lastSeen) {
			g.ended = g.lastSeen.Add(time.Duration(3+w.Rand.IntN(50)) * time.Second)
		}
		s.superseded = g.id
		s.end(at)
		h.add(g)
	}
}
