// Package activity seeds months of everyday use: sessions on people's devices,
// sign-ins and failures, administrators' changes in the audit log, the emails
// the platform sent, and each organisation's billing history.
package activity

import (
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// Seed writes every organisation's history up to today. What goes through the
// API's services runs first, since At moves whatever is written while it
// runs; the bulk of the history is then written directly, in one pass.
func Seed(w *world.World) {
	h := newHistory(w)
	h.billingHistory()
	h.adminChanges()
	h.salesLeads()

	sups := h.mailStories()
	h.planTrips()
	for _, o := range w.Orgs {
		for _, p := range o.People {
			h.signIns(o, p)
		}
	}
	for _, o := range w.Orgs {
		for _, p := range o.People {
			h.keepSignedIn(o, p)
		}
	}
	for _, o := range w.Orgs {
		for _, g := range guests(o) {
			h.guestSwitches(g.p, o, g.since, g.rate)
		}
	}
	var evs []accountEvent
	for _, o := range w.Orgs {
		evs = append(evs, h.accountEvents(o)...)
	}
	slices.SortStableFunc(evs, func(a, b accountEvent) int { return a.at.Compare(b.at) })
	for _, ev := range evs {
		h.apply(ev)
	}
	for _, o := range w.Orgs {
		for _, p := range o.People {
			h.endAtDeparture(p)
			h.limitLive(p)
			h.markExpiries(p)
		}
	}
	h.sortSessions()
	for _, s := range h.sessions {
		h.emit(s)
	}
	var surges []string
	for _, o := range w.Orgs {
		h.mistypes(o)
		as := h.attacks(o)
		for _, a := range as {
			h.carryOut(o, a)
		}
		if recentlyAttacked(as, w.Now) {
			surges = append(surges, o.Spec.Name)
		}
	}
	h.write()
	h.writeSuppressions(sups)
	h.touchConnections()
	groupProvisioning(w)
	h.notes(surges)
	// The events the seed's service calls queued were delivered long ago:
	// the API's dispatcher must not send months of history to webhooks today.
	w.Exec("mark seeded events delivered", `UPDATE platform.outbox SET published_at = created_at + interval '2 seconds' WHERE published_at IS NULL`)
}

// newHistory reads what the earlier steps set up that sign-ins depend on:
// each organisation's session policy, linked social accounts and email or
// SMS factors.
func newHistory(w *world.World) *history {
	h := &history{
		w: w, policies: map[uuid.UUID]policy{}, social: map[uuid.UUID]bool{}, socialSeeded: map[uuid.UUID]bool{},
		otp: map[uuid.UUID]otpFactor{}, noMagic: map[*world.Person]window{}, trips: map[*world.Person]trip{},
		of: map[*world.Person][]*session{},
	}
	ids := make([]uuid.UUID, 0, len(w.Orgs))
	for _, o := range w.Orgs {
		ids = append(ids, o.ID)
		h.policies[o.ID] = policy{maxAge: w.Cfg.SessionMaxAge, idle: w.Cfg.SessionIdleTimeout}
	}
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT tenant_id, EXTRACT(EPOCH FROM session_max_age)::bigint, EXTRACT(EPOCH FROM session_idle_timeout)::bigint,
		       COALESCE(max_sessions, 0)
		FROM tenant.security_policies WHERE tenant_id = ANY($1)`, ids)
	w.Check(err, "read session policies")
	for rows.Next() {
		var id uuid.UUID
		var maxAge, idle int64
		var limit int
		w.Check(rows.Scan(&id, &maxAge, &idle, &limit), "scan session policy")
		h.policies[id] = policy{maxAge: time.Duration(maxAge) * time.Second, idle: time.Duration(idle) * time.Second, maxSessions: limit}
	}
	rows.Close()

	rows, err = w.Admin.Query(w.Ctx, `
		SELECT tenant_id, user_id FROM account.external_identities
		WHERE tenant_id = ANY($1) AND provider NOT LIKE 'ldap%'`, ids)
	w.Check(err, "read linked social accounts")
	for rows.Next() {
		var tenant, user uuid.UUID
		w.Check(rows.Scan(&tenant, &user), "scan linked social account")
		h.social[user], h.socialSeeded[tenant] = true, true
	}
	rows.Close()

	rows, err = w.Admin.Query(w.Ctx, `
		SELECT DISTINCT ON (user_id) user_id, id, channel, destination
		FROM auth.mfa_otp_factors WHERE verified_at IS NOT NULL
		ORDER BY user_id, created_at`)
	w.Check(err, "read email and SMS factors")
	for rows.Next() {
		var user uuid.UUID
		var f otpFactor
		w.Check(rows.Scan(&user, &f.id, &f.channel, &f.destination), "scan email or SMS factor")
		h.otp[user] = f
	}
	rows.Close()
	return h
}

// guest is someone who holds a role in an organisation other than their own.
type guest struct {
	p     *world.Person
	since time.Time
	rate  float64 // the share of working days they switch to it
}

// guests are o's members from other organisations, its owner included when
// their home is elsewhere.
func guests(o *world.Org) []guest {
	var out []guest
	if o.Owner != nil && o.Owner.Org != o {
		out = append(out, guest{o.Owner, o.Spec.Since, 0.15})
	}
	for _, p := range o.Guests {
		for _, r := range p.GuestOf {
			if r.Org == o {
				out = append(out, guest{p, r.Since, 0.35})
			}
		}
	}
	return out
}

// touchConnections dates each organisation's SAML and LDAP connections and
// each passkey by the last sign-in that used them.
func (h *history) touchConnections() {
	w := h.w
	saml, ldap := map[uuid.UUID]time.Time{}, map[uuid.UUID]time.Time{}
	passkeys := map[uuid.UUID]time.Time{}
	for _, s := range h.sessions {
		switch s.first {
		case "saml":
			saml[s.org.ID] = maxTime(saml[s.org.ID], s.created)
		case "ldap":
			ldap[s.org.ID] = maxTime(ldap[s.org.ID], s.created)
		case "passkey":
			passkeys[s.p.ID] = maxTime(passkeys[s.p.ID], s.created)
		}
	}
	batch := &pgx.Batch{}
	for _, o := range w.Orgs {
		if t, ok := saml[o.ID]; ok {
			batch.Queue(`UPDATE tenant.saml_connections SET last_login_at = $2 WHERE tenant_id = $1 AND status = 'active'`, o.ID, us(t))
		}
		if t, ok := ldap[o.ID]; ok {
			batch.Queue(`UPDATE tenant.ldap_connections SET last_login_at = $2 WHERE tenant_id = $1 AND status = 'active'`, o.ID, us(t))
		}
	}
	for user, t := range passkeys {
		batch.Queue(`
			UPDATE auth.passkey_credentials SET last_used_at = $2
			WHERE id = (SELECT id FROM auth.passkey_credentials WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1)`, user, us(t))
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "date connections and passkeys by their last use")
}

// notes adds the history to the closing summary: what to look at, and where.
func (h *history) notes(surges []string) {
	w := h.w
	const section = "Activity, audit and billing history (last 90 days)"
	failed := 0
	for _, e := range h.events {
		if e.e.Action == "auth.sign_in_failed" {
			failed++
		}
	}
	w.Note(section, "%d sessions (%d live now), %d failed sign-ins, %d audit rows, %d emails — dashboard, /activity, /audit-logs",
		len(h.sessions), h.sessionsLive(), failed, len(h.events), len(h.mails))
	w.Note(section, "Each test account: 2–3 live sessions (computer, phone, home laptop), a trip abroad, ended ones — /account/sessions")
	w.Note(section, "Failed sign-ins up on the day before (dashboard insight): %s", strings.Join(surges, ", "))
	w.Note(section, "Invoices carry GST as if BILLING_TAX_ENABLED=true and BILLING_SELLER_STATE=%s; set both for new ones to match", sellerState)
}
