package activity

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// attack is a credential-stuffing run from one source against an
// organisation's sign-in page: addresses from a leaked list, most of which
// have no account there. The security step writes the password sprays and
// the account lockouts.
type attack struct {
	at   time.Time
	from world.Device
	n    int // attempts; 0 for the usual 18–29, fewer than the 30 accounts that throttle a source
}

// attacks plans the runs against o since it opened: a few over the last
// fortnight, and fresh ones in the last 24 hours at the larger
// organisations, so failed sign-ins are well up on the day before and the
// dashboard's insight fires. An organisation open to self-registration was
// probed the day before too, so its rise is milder. Where only the office
// network may sign in, outside attempts are refused before any password is
// checked, so there are none.
func (h *history) attacks(o *world.Org) []attack {
	w := h.w
	if len(o.People) < 12 || len(o.Spec.Features.Apps) == 0 || o.Spec.Features.IPAllowlist {
		return nil
	}
	opened := o.Spec.Since.Add(24 * time.Hour)
	var out []attack
	for range 2 + w.Rand.IntN(3) {
		if at := w.Between(maxTime(w.Days(14), opened), w.Days(3)); at.After(opened) {
			out = append(out, attack{at: at, from: world.Pick(w, world.Attackers)})
		}
	}
	recent := func(n int) attack {
		return attack{at: w.Between(w.Days(0.9), w.Days(0.1)), from: world.Pick(w, world.Attackers), n: n}
	}
	switch {
	case o.Spec.Features.SelfSignup:
		out = append(out, attack{at: w.Between(w.Days(1.9), w.Days(1.1)), from: world.Pick(w, world.Attackers), n: 12}, recent(22))
	case len(o.People) >= 40:
		out = append(out, recent(0), recent(0))
	case len(o.People) >= 20:
		out = append(out, recent(0))
	}
	return out
}

// carryOut writes a run's failed sign-ins, as the API records them: an
// address with no account fails anonymously; a real one fails as its owner,
// once or twice each, short of locking it.
func (h *history) carryOut(o *world.Org, a attack) {
	w := h.w
	var targets []*world.Person
	for _, p := range o.Members() {
		if p.Status == world.StatusActive && p.Org == o && p.Joined.Before(a.at) {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return
	}
	n := a.n
	if n == 0 {
		n = 18 + w.Rand.IntN(12)
	}
	t := a.at
	for range n {
		if w.Chance(0.75) {
			h.failure(o, nil, a.from, t, "password", "unknown_account")
		} else {
			h.failure(o, world.Pick(w, targets), a.from, t, "password", "wrong_password")
		}
		t = t.Add(time.Duration(3+w.Rand.IntN(14)) * time.Second)
	}
}

// mistypes records the everyday failures at o's sign-in page over the last
// fortnight: members typing an address that has no account, a few a day.
func (h *history) mistypes(o *world.Org) {
	w := h.w
	if len(o.People) < 12 {
		return
	}
	for d := 14; d >= 0; d-- {
		day := w.Days(float64(d))
		p := someone(w, o, func(q *world.Person) bool { return q.Joined.Before(day) })
		if p == nil {
			continue
		}
		rate := float64(len(o.People)) / 25
		if !workingDay(p, day) {
			rate *= 0.3
		}
		for range poisson(w, rate) {
			q := someone(w, o, func(q *world.Person) bool { return q.Joined.Before(day) })
			t := w.WorkHours(day, q.Loc)
			if t.After(w.Now) {
				continue
			}
			h.failure(o, nil, h.device(o, q, t, "desktop"), t, "password", "unknown_account")
		}
	}
}

// recentlyAttacked reports whether any of as came in the last 24 hours.
func recentlyAttacked(as []attack, now time.Time) bool {
	for _, a := range as {
		if a.at.After(now.Add(-24 * time.Hour)) {
			return true
		}
	}
	return false
}
