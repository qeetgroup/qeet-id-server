package activity

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// historyDays is how far back sign-in history goes: the analytics compare 30
// days with the 30 before and chart eight weeks, and the platform keeps
// sign-in context and email records for 90 days.
const historyDays = 90

// session is one API or console session, as auth.sessions stores it.
type session struct {
	id       uuid.UUID
	p        *world.Person
	org      *world.Org // the organisation signed in to
	dev      world.Device
	method   string // the sign-in method recorded on auth.login_succeeded
	first    string // its first factor: password, saml, ldap, social, magic_link, passkey, tenant_switch
	factor   string // second_factor: mfa, passkey or ""
	created  time.Time
	lastSeen time.Time
	ended    time.Time // revoked_at; zero while the session hasn't been ended
	expires  time.Time
	idle     time.Duration
	// superseded is the session that replaced this one when its person
	// switched organisation.
	superseded uuid.UUID
	// typos is how many wrong passwords preceded the sign-in.
	typos int
	// previous is the session a switch of organisation came from.
	previous *session
}

// idleEnd is when s ends unless renewed first.
func (s *session) idleEnd() time.Time {
	end := s.lastSeen.Add(s.idle)
	if s.expires.Before(end) {
		return s.expires
	}
	return end
}

// liveAt reports whether s could still be used at t.
func (s *session) liveAt(t time.Time) bool {
	return !s.created.After(t) && (s.ended.IsZero() || s.ended.After(t)) && s.idleEnd().After(t)
}

// end ends s at t; it is not used after.
func (s *session) end(t time.Time) {
	s.ended = t
	if s.lastSeen.After(t) {
		s.lastSeen = t
	}
}

// event is an audit row to write at a time.
type event struct {
	at time.Time
	e  audit.Event
}

// signInContext is a sign-in's device and country, as the risk engine keeps
// them (auth.login_context_history).
type signInContext struct {
	tenant, user uuid.UUID
	deviceKey    string
	country      string
	seen         time.Time
}

// policy is an organisation's session bounds and limit.
type policy struct {
	maxAge, idle time.Duration
	maxSessions  int
}

// history is everyone's sign-in history as it is generated, written in bulk
// at the end.
type history struct {
	w        *world.World
	policies map[uuid.UUID]policy
	// social marks people with a linked social account; socialSeeded marks the
	// organisations where any is linked, so the others fall back to a share
	// of their people.
	social       map[uuid.UUID]bool
	socialSeeded map[uuid.UUID]bool
	otp          map[uuid.UUID]otpFactor // a person's verified email or SMS factor
	// noMagic is when sign-in links didn't reach a person: their address was
	// suppressed.
	noMagic map[*world.Person]window

	sessions []*session
	of       map[*world.Person][]*session // each person's sessions
	events   []event
	contexts []signInContext
	mails    []*mail
	trips    map[*world.Person]trip

	requests int
}

// window is a span of time; a zero end is open.
type window struct{ from, to time.Time }

// contains reports whether t falls in the window.
func (v window) contains(t time.Time) bool {
	return !t.Before(v.from) && (v.to.IsZero() || t.Before(v.to))
}

// trip is a few days a person spent abroad.
type trip struct {
	from, to time.Time
	dev      world.Device
}

// requestID returns a request id in the API's format: the pod's host name,
// a per-process base and a counter.
func (h *history) requestID() string {
	h.requests++
	pods := []string{"qeet-id-api-6f9d8c7b5-x2k4q/Xk3pQ9rT2b", "qeet-id-api-6f9d8c7b5-m7wzt/aL5nV8cE1d", "qeet-id-api-6f9d8c7b5-q4hfj/Tg2sR6yP0m"}
	return fmt.Sprintf("%s-%06d", pods[h.requests%len(pods)], 1000+h.requests)
}

// audit queues an audit row.
func (h *history) audit(at time.Time, e audit.Event) {
	h.events = append(h.events, event{at: at, e: e})
}

// add records a new session.
func (h *history) add(s *session) {
	h.sessions = append(h.sessions, s)
	h.of[s.p] = append(h.of[s.p], s)
}

// byPerson returns p's sessions, oldest first.
func (h *history) byPerson(p *world.Person) []*session {
	out := slices.Clone(h.of[p])
	slices.SortStableFunc(out, func(a, b *session) int { return a.created.Compare(b.created) })
	return out
}

func ptr[T any](v T) *T { return &v }

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// minutes is n minutes.
func minutes(n float64) time.Duration { return time.Duration(n * float64(time.Minute)) }

// jitter is a random duration in [lo, hi) minutes.
func jitter(w *world.World, lo, hi float64) time.Duration {
	return minutes(lo + (hi-lo)*w.Rand.Float64())
}

// localTime is the instant at hour:minute on the local day of t in loc, with
// random seconds.
func localTime(w *world.World, t time.Time, loc *time.Location, minuteOfDay int) time.Time {
	l := t.In(loc)
	return time.Date(l.Year(), l.Month(), l.Day(), 0, 0, w.Rand.IntN(60), 0, loc).Add(time.Duration(minuteOfDay) * time.Minute).UTC()
}

// poisson draws from a Poisson distribution with mean lambda.
func poisson(w *world.World, lambda float64) int {
	if lambda <= 0 {
		return 0
	}
	l, k, p := math.Exp(-lambda), 0, 1.0
	for {
		p *= w.Rand.Float64()
		if p <= l {
			return k
		}
		k++
	}
}
