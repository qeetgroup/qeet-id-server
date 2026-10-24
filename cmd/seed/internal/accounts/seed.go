// Package accounts seeds each organisation's own settings and its people's
// account states: profile and logo, branding, domains, email templates,
// security, sign-in and retention policies, invitations, suspended and deleted
// accounts, group roles and templates, notifications and data requests.
package accounts

import (
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// seeder carries what the identity step's parts share: the API's handlers for
// requests made as an administrator, and the events later parts turn into
// notifications and summary lines.
type seeder struct {
	w   *world.World
	api *api
	// events are what happened in each organisation that its administrators
	// were told about, for the notification bell.
	events map[uuid.UUID][]event
	// links are pending invitations' accept links, for the summary.
	links []string
	// enrol is the account made to set up MFA at its next sign-in.
	enrol *enrolment
}

// enrolment is who was required to set up MFA, when and by whom.
type enrolment struct {
	person, by *world.Person
	at         time.Time
}

// event is something an organisation's administrators were notified of. The
// flags also tell billing admins, security analysts and auditors, or helpdesk.
type event struct {
	at                          time.Time
	kind, title, detail, href   string
	billing, security, helpdesk bool
}

// Seed applies every organisation's settings and account states.
func Seed(w *world.World) {
	// With no mail server the invitation emails are logged, a line each; the
	// summary prints the links worth having.
	defer slog.SetLogLoggerLevel(slog.SetLogLoggerLevel(slog.LevelWarn))
	s := &seeder{w: w, api: newAPI(w), events: map[uuid.UUID][]event{}}
	for _, o := range w.Orgs {
		s.profile(o)
		s.domains(o)
		s.policies(o)
		s.templates(o)
		s.groups(o)
		s.invitations(o)
		s.exports(o)
		s.accounts(o)
		s.erasures(o)
	}
	s.enrolmentDemo()
	s.notifications()
	s.summary()
}

// tell records an event for o's administrators.
func (s *seeder) tell(o *world.Org, e event) {
	s.events[o.ID] = append(s.events[o.ID], e)
}

// by is who in o makes an administrative change at t: the first person
// holding one of roles (IT Admin, then Admin, by default) who had been there a
// week and could still act, else the owner.
func by(o *world.Org, t time.Time, roles ...string) *world.Person {
	if len(roles) == 0 {
		roles = []string{world.RoleITAdmin, world.RoleAdmin}
	}
	for _, role := range roles {
		for _, p := range o.People {
			if p.Role == role && p.ID != uuid.Nil && t.Sub(p.Joined) > 7*24*time.Hour && activeAt(p, t) {
				return p
			}
		}
	}
	return o.Owner
}

// activeAt reports whether p could act at t: joined, and not yet suspended or
// deleted.
func activeAt(p *world.Person, t time.Time) bool {
	return !t.Before(p.Joined) && (p.Status == world.StatusActive || t.Before(p.Since))
}

// after returns t, or a minute past not when t is no later: nothing happens
// before the organisation or the people involved existed.
func after(t, not time.Time) time.Time {
	if t.After(not) {
		return t
	}
	return not.Add(time.Minute)
}

// clamp keeps t at least a minute in the past.
func clamp(w *world.World, t time.Time) time.Time {
	if limit := w.Now.Add(-time.Minute); t.After(limit) {
		return limit
	}
	return t
}
