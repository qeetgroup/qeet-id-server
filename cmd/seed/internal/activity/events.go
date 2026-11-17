package activity

import (
	"slices"
	"strings"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// planTrips sends every test account, and a few others, abroad for a few
// days in the last month, so their session lists show a sign-in from another
// country. Organizations that allow only their office network are skipped:
// sign-in from abroad is refused there.
func (h *history) planTrips() {
	w := h.w
	i := 0
	for _, o := range w.Orgs {
		if o.Spec.Features.IPAllowlist {
			continue
		}
		for _, p := range o.People {
			if p.Status != world.StatusActive || p.Unverified || automation(p) {
				continue
			}
			if p.Login == "" && !w.Chance(0.04) {
				continue
			}
			from := w.Days(float64(17 + (i*5)%14))
			from = localTime(w, from, p.Loc, 0)
			tr := trip{from: from, to: from.Add(time.Duration(3+i%2) * 24 * time.Hour), dev: world.Abroad[i%len(world.Abroad)]}
			if p.Joined.Before(tr.from.Add(-14 * 24 * time.Hour)) {
				h.trips[p] = tr
				i++
			}
		}
	}
}

// keepSignedIn gives a test account the live sessions a tester expects to
// see: its computer signed in this morning, its phone a few hours ago and,
// for some, a personal laptop last night.
func (h *history) keepSignedIn(o *world.Org, p *world.Person) {
	w := h.w
	if p.Login == "" || p.Status != world.StatusActive {
		return
	}
	local := w.Now.In(p.Loc)
	at := localTime(w, w.Now, p.Loc, 520+w.Rand.IntN(40))
	desk := h.newSession(o, p, at, "desktop", w.Now.Sub(at))
	desk.lastSeen, desk.ended = w.Now.Add(-jitter(w, 2, 15)), time.Time{}
	if local.Hour() < 10 {
		// Too early today: still signed in from yesterday evening.
		desk.created = localTime(w, w.Days(1), p.Loc, 1020+w.Rand.IntN(60))
		desk.lastSeen, desk.expires = desk.created.Add(jitter(w, 60, 150)), desk.created.Add(h.policies[o.ID].maxAge)
	}

	at = w.Now.Add(-jitter(w, 90, 240))
	if local.Hour() < 12 {
		at = localTime(w, w.Days(1), p.Loc, 1230+w.Rand.IntN(60))
	}
	phone := h.newSession(o, p, at, "mobile", jitter(w, 5, 25))
	phone.ended = time.Time{}

	if o.Spec.Features.IPAllowlist || int(p.ID[14])%2 == 0 {
		return
	}
	at = localTime(w, w.Days(1), p.Loc, 1260+w.Rand.IntN(45))
	laptop := h.newSession(o, p, at, "desktop", jitter(w, 30, 90))
	laptop.ended = time.Time{}
	laptop.dev = personalLaptop(p)
}

// personalLaptop is p's own computer at home, as opposed to their work one.
func personalLaptop(p *world.Person) world.Device {
	d := p.Device
	if strings.Contains(d.UserAgent, "Macintosh") {
		d.Label, d.UserAgent = "Firefox on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:156.0) Gecko/20100101 Firefox/156.0"
	} else {
		d.Label, d.UserAgent = "Firefox on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0"
	}
	return d
}

// accountEvent is something that ended a person's sessions: a password
// change or reset, an administrator's action, or the person signing out
// their other devices.
type accountEvent struct {
	p    *world.Person
	o    *world.Org
	at   time.Time
	kind string // password_changed, password_reset, password_set, admin_revoked, others_revoked
	by   *world.Person
}

// accountEvents decides o's account events: a few people change or reset
// their password, a help-desk administrator sets a password, a security
// administrator signs someone out everywhere, and every test account signs
// out its other devices once. Lockouts are the security step's.
func (h *history) accountEvents(o *world.Org) []accountEvent {
	w := h.w
	var out []accountEvent
	var eligible []*world.Person
	for _, p := range o.People {
		if p.Login == "" && !p.Unverified && !automation(p) && p.Joined.Before(w.Days(30)) {
			eligible = append(eligible, p)
		}
		if p.Login != "" && p.Status == world.StatusActive {
			out = append(out, accountEvent{p: p, o: o, kind: "others_revoked", at: h.workTime(p, w.Days(6+w.Rand.Float64()*3))})
		}
	}
	if len(eligible) == 0 {
		return out
	}
	when := func(p *world.Person) time.Time {
		end := w.Days(2)
		if p.Status != world.StatusActive {
			end = p.Since.Add(-24 * time.Hour)
		}
		return h.workTime(p, w.Between(maxTime(p.Joined.Add(7*24*time.Hour), w.Days(85)), end))
	}
	for _, p := range eligible {
		switch r := w.Rand.Float64(); {
		case r < 0.1 && !ssoOnly(o, p):
			out = append(out, accountEvent{p: p, o: o, kind: "password_changed", at: when(p)})
		case r < 0.13 && !ssoOnly(o, p):
			out = append(out, accountEvent{p: p, o: o, kind: "password_reset", at: when(p)})
		}
	}
	pick := func(ok func(*world.Person) bool) *world.Person {
		var c []*world.Person
		for _, p := range eligible {
			if ok(p) {
				c = append(c, p)
			}
		}
		if len(c) == 0 {
			return nil
		}
		return world.Pick(w, c)
	}
	if len(o.People) >= 12 {
		if p := pick(func(p *world.Person) bool { return !ssoOnly(o, p) && p.Role != world.RoleOwner }); p != nil {
			at := when(p)
			if by := actorAt(o, at, world.RoleHelpdesk, world.RoleITAdmin, world.RoleAdmin); by != nil && by != p {
				out = append(out, accountEvent{p: p, o: o, kind: "password_set", at: at, by: by})
			}
		}
	}
	if len(o.People) >= 30 {
		if p := pick(func(p *world.Person) bool { return p.Role != world.RoleOwner }); p != nil {
			at := when(p)
			if by := actorAt(o, at, world.RoleSecurity, world.RoleITAdmin, world.RoleAdmin); by != nil && by != p {
				out = append(out, accountEvent{p: p, o: o, kind: "admin_revoked", at: at, by: by})
			}
		}
	}
	return out
}

// ssoOnly reports whether p signs in only through o's identity provider or
// directory, so has no password of their own to change.
func ssoOnly(o *world.Org, p *world.Person) bool {
	return p.Provisioned != ""
}

// actorAt is an active person in o holding one of roles (tried in order)
// who had joined well before t, or nil.
func actorAt(o *world.Org, t time.Time, roles ...string) *world.Person {
	for _, role := range roles {
		for _, p := range o.People {
			if p.Role == role && p.Joined.Before(t.Add(-7*24*time.Hour)) && (p.Status == world.StatusActive || p.Since.After(t)) {
				return p
			}
		}
	}
	if o.Owner.Org == o && o.Owner.Joined.Before(t) {
		return o.Owner
	}
	return nil
}

// workTime moves t into p's working hours.
func (h *history) workTime(p *world.Person, t time.Time) time.Time {
	for !workingDay(p, t) {
		t = t.Add(-24 * time.Hour)
	}
	return h.w.WorkHours(t, p.Loc)
}

// workDayAfter is a time in p's working hours on the first working day after
// t's.
func (h *history) workDayAfter(p *world.Person, t time.Time) time.Time {
	t = t.Add(24 * time.Hour)
	for !workingDay(p, t) {
		t = t.Add(24 * time.Hour)
	}
	return h.w.WorkHours(t, p.Loc)
}

// apply carries out an account event: the sessions it ends, its audit rows
// and, for a reset, the email and the sign-in that follows.
func (h *history) apply(ev accountEvent) {
	w := h.w
	p, o, t := ev.p, ev.o, ev.at
	if p.Status != world.StatusActive && !t.Before(p.Since) {
		return
	}
	var kept *session
	var live []*session
	for _, s := range h.byPerson(p) {
		if s.liveAt(t) {
			live = append(live, s)
		}
	}
	endLive := func(keep *session) int {
		n := 0
		for _, s := range live {
			if s != keep {
				s.end(t)
				n++
			}
		}
		return n
	}
	counts := func(n int) map[string]any {
		return map[string]any{"revoked_sessions": n, "revoked_login_sessions": 0, "revoked_app_grants": 0,
			"revoked_trusted_devices": 0, "ended_pending_authorizations": 0}
	}
	home := p.Org.ID
	switch ev.kind {
	case "others_revoked", "password_changed":
		if len(live) == 0 {
			return
		}
		kept = live[len(live)-1]
		n := endLive(kept)
		meta := map[string]any{"revoked_sessions": n, "kept_session_id": kept.id}
		action := "auth.other_sessions_revoked"
		if ev.kind == "password_changed" {
			meta = counts(n)
			meta["kept_session_id"] = kept.id
			action = "auth.password_changed"
		}
		h.audit(t, audit.Event{OrganizationID: ptr(kept.org.ID), ActorUserID: ptr(p.ID), ActorType: "user", Action: action,
			ResourceType: "user", ResourceID: ptr(p.ID), IP: kept.dev.IP, UserAgent: kept.dev.UserAgent,
			RequestID: h.requestID(), Metadata: meta})
	case "password_reset":
		dev := h.device(o, p, t, "desktop")
		asked := t.Add(-jitter(w, 2, 5))
		h.audit(asked, audit.Event{OrganizationID: ptr(home), ActorType: "anonymous", Action: "auth.password_reset_requested",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: dev.IP, UserAgent: dev.UserAgent, RequestID: h.requestID(),
			Metadata: map[string]any{"app": ""}})
		h.mail(nil, p.Email, "", asked.Add(time.Second))
		meta := counts(endLive(nil))
		meta["sessions_revoked"] = true
		h.audit(t, audit.Event{OrganizationID: ptr(home), ActorUserID: ptr(p.ID), ActorType: "system", Action: "auth.password_reset_confirmed",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: dev.IP, UserAgent: dev.UserAgent, RequestID: h.requestID(), Metadata: meta})
		after := t.Add(jitter(w, 1, 3))
		s := h.newSession(o, p, after, "desktop", h.duration(p, after, "desktop", true))
		s.first, s.typos = "password", 0
		s.method, s.factor = h.complete(o, p, after, "password")
		s.dev = dev
	case "password_set":
		meta := counts(endLive(nil))
		meta["sessions_revoked"] = true
		h.audit(t, audit.Event{OrganizationID: ptr(o.ID), ActorUserID: ptr(ev.by.ID), ActorType: "user", Action: "user.password_set",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: officeIP(ev.by), UserAgent: ev.by.Device.UserAgent,
			RequestID: h.requestID(), Metadata: meta})
	case "admin_revoked":
		h.audit(t, audit.Event{OrganizationID: ptr(o.ID), ActorUserID: ptr(ev.by.ID), ActorType: "user", Action: "session.admin_revoked_all",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: officeIP(ev.by), UserAgent: ev.by.Device.UserAgent,
			RequestID: h.requestID(), Metadata: counts(endLive(nil))})
	}
}

// officeIP is p's address at their office, or at home when they have none.
// Where only the office network may sign in, it is the headquarters'.
func officeIP(p *world.Person) string {
	if p.Org.Spec.Features.IPAllowlist {
		if c, ok := offices[p.Org.Spec.City]; ok {
			return c.Office
		}
	}
	if c, ok := offices[p.City]; ok && p.Country == p.Org.Spec.Country {
		return c.Office
	}
	return p.Device.IP
}

// failure records a failed sign-in by p (nil: an address with no account)
// to o, as RecordSignInFailure does.
func (h *history) failure(o *world.Org, p *world.Person, dev world.Device, t time.Time, method, reason string) {
	e := audit.Event{OrganizationID: ptr(o.ID), ActorType: "anonymous", Action: "auth.sign_in_failed", IP: dev.IP, UserAgent: dev.UserAgent,
		Metadata: map[string]any{"method": method, "reason": reason, "network": dev.IP}}
	if p != nil {
		e.ActorUserID, e.ActorType, e.ResourceType, e.ResourceID = ptr(p.ID), "user", "user", ptr(p.ID)
	}
	h.audit(t, e)
}

// endAtDeparture ends the sessions of someone suspended or deleted when they
// left, as the API does.
func (h *history) endAtDeparture(p *world.Person) {
	if p.Status == world.StatusActive {
		return
	}
	for _, s := range h.byPerson(p) {
		if s.liveAt(p.Since) {
			s.end(p.Since)
		}
	}
}

// limitLive leaves p one live session per browser, signed out of the older
// before signing in again, and keeps them within their organization's limit
// on simultaneous sessions (four in any case): the oldest were ended when a
// newer one pushed past it.
func (h *history) limitLive(p *world.Person) {
	limit := 4
	if pol := h.policies[p.Org.ID]; pol.maxSessions > 0 && pol.maxSessions < limit {
		limit = pol.maxSessions
	}
	var live []*session
	latest := map[string]*session{}
	for _, s := range h.byPerson(p) {
		if !s.liveAt(h.w.Now) {
			continue
		}
		if prev := latest[s.dev.UserAgent]; prev != nil && prev.org == s.org {
			prev.end(s.created.Add(-jitter(h.w, 0.2, 3)))
			live = slices.DeleteFunc(live, func(x *session) bool { return x == prev })
		}
		latest[s.dev.UserAgent] = s
		live = append(live, s)
	}
	for i := 0; len(live)-i > limit; i++ {
		live[i].end(live[i+limit].created)
	}
}

// markExpiries records, for some sessions that ran past their idle timeout,
// the refresh that found them expired when their person came back on the
// same device: the API ends them then and audits auth.session_expired.
func (h *history) markExpiries(p *world.Person) {
	w := h.w
	ss := h.byPerson(p)
	for i, s := range ss {
		if !s.ended.IsZero() || s.first == "tenant_switch" || !s.idleEnd().Before(w.Now) || !w.Chance(0.2) {
			continue
		}
		for _, next := range ss[i+1:] {
			if next.created.Before(s.idleEnd()) || next.created.After(s.idleEnd().Add(72*time.Hour)) {
				continue
			}
			if next.dev.UserAgent != s.dev.UserAgent || next.org != s.org {
				continue
			}
			at := next.created.Add(-4 * time.Second)
			reason := "idle"
			if !s.expires.After(s.lastSeen.Add(s.idle)) {
				reason = "max_age"
			}
			s.ended = at
			h.audit(at, audit.Event{OrganizationID: ptr(s.org.ID), ActorUserID: ptr(p.ID), ActorType: "system",
				Action: "auth.session_expired", ResourceType: "session", ResourceID: ptr(s.id),
				IP: next.dev.IP, UserAgent: next.dev.UserAgent,
				Metadata: map[string]any{"session_id": s.id, "reason": reason}})
			break
		}
	}
}

// sortSessions orders the sessions by when they were opened.
func (h *history) sortSessions() {
	slices.SortStableFunc(h.sessions, func(a, b *session) int { return a.created.Compare(b.created) })
}

// sessionsLive counts the sessions live now.
func (h *history) sessionsLive() int {
	n := 0
	for _, s := range h.sessions {
		if s.liveAt(h.w.Now) {
			n++
		}
	}
	return n
}
