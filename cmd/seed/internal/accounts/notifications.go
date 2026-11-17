package accounts

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// inbox is how far back the bell's history goes.
const inbox = 21 * 24 * time.Hour

// note is one notification for one person.
type note struct {
	organization uuid.UUID
	event
}

// notifications fills the bell of every test account and every owner: alerts
// about their own account (new sign-ins, factors added) and, for those who
// administer an organization, what happened in it over the last three weeks.
// Each person opened the bell now and then, which marked everything read;
// what arrived since is unread.
func (s *seeder) notifications() {
	w := s.w
	seen := map[*world.Person]bool{}
	for _, o := range w.Orgs {
		s.orgEvents(o)
	}
	for _, o := range w.Orgs {
		for _, p := range append([]*world.Person{o.Owner}, o.People...) {
			if seen[p] || p.Status != world.StatusActive || (p.Login == "" && p != o.Owner) {
				continue
			}
			seen[p] = true
			s.deliver(p, s.notesFor(p))
		}
	}
}

// orgEvents adds what the organization's administrators hear about besides
// the steps' own events: billing, trials, adoption and set-up nudges.
func (s *seeder) orgEvents(o *world.Org) {
	w := s.w
	switch o.Spec.Billing {
	case "past_due":
		s.tell(o, event{at: w.WorkHours(w.Days(3), o.Loc), kind: "alert", title: "Payment failed",
			detail: fmt.Sprintf("We couldn't charge your card for the %s plan. Update the payment method to keep its features.", planName(o.Spec.Plan)),
			href:   "/settings/billing", billing: true})
	case "trialing":
		left := o.Spec.Since.Add(14 * 24 * time.Hour).Sub(w.Now)
		s.tell(o, event{at: o.Spec.Since.Add(7 * 24 * time.Hour), kind: "warning", title: "Your Pro trial ends in 7 days",
			detail: fmt.Sprintf("Add a payment method to keep SSO, audit export and ABAC after the trial ends in %d days.", int(left.Hours()/24)),
			href:   "/settings/billing", billing: true})
	case "active":
		if !o.Has("starter") {
			break
		}
		if o.Spec.Annual {
			renews := o.Spec.Since.AddDate(1, 0, 0)
			for renews.Before(w.Now) {
				renews = renews.AddDate(1, 0, 0)
			}
			if renews.Sub(w.Now) < 30*24*time.Hour {
				s.tell(o, event{at: w.WorkHours(renews.Add(-14*24*time.Hour), o.Loc), kind: "info",
					title:  fmt.Sprintf("%s plan renews on %s", planName(o.Spec.Plan), renews.In(o.Loc).Format("2 Jan 2006")),
					detail: "Your annual subscription renews automatically. Check the billing details and purchase order number before the invoice is issued.",
					href:   "/settings/billing", billing: true})
			}
			break
		}
		paid := time.Date(w.Now.Year(), w.Now.Month(), o.Spec.Since.Day(), 7, 0, 0, 0, o.Loc)
		if paid.After(w.Now) {
			paid = paid.AddDate(0, -1, 0)
		}
		s.tell(o, event{at: paid, kind: "success", title: "Payment received",
			detail: fmt.Sprintf("Your card was charged for this month's %s plan. The invoice is in Billing.", planName(o.Spec.Plan)),
			href:   "/settings/billing", billing: true})
	}

	// MFA adoption, as the dashboard counts it (authenticator apps), where
	// second factors are optional.
	if o.Spec.Features.MFA == "optional" && len(o.People) >= 10 {
		active, totp := 0, 0
		for _, p := range o.Active() {
			active++
			if p.HasFactor("totp") {
				totp++
			}
		}
		if share := 100 * totp / max(active, 1); share < 50 {
			s.tell(o, event{at: w.WorkHours(w.Days(5), o.Loc), kind: "warning", title: fmt.Sprintf("MFA adoption is %d%%", share),
				detail: "Fewer than half your people use an authenticator app. Consider requiring MFA in the security policy.",
				href:   "/analytics", security: true})
		}
	}
	switch o.Spec.Slug {
	case "vertex":
		s.tell(o, event{at: o.Spec.Since.Add(50 * time.Hour), kind: "info", title: "Okta SAML connection saved as a draft",
			detail: "Test the connection, then activate it to let people sign in with Okta.", href: "/auth/connections/saml"})
	case "fjord":
		s.tell(o, event{at: o.Spec.Since.Add(2 * time.Minute), kind: "success", title: "Welcome to Qeet ID",
			detail: "Your organisation is ready. Invite your team and connect your first application.", href: "/"})
		s.tell(o, event{at: o.Spec.Since.Add(3 * time.Hour), kind: "info", title: "Connect your first application",
			detail: "Register an OIDC application so your users can sign in with Qeet ID.", href: "/applications"})
	}
	if o.Spec.Features.SSO != "" && o.Spec.Features.SSOStatus == "active" && o.Has("enterprise") {
		s.tell(o, event{at: w.WorkHours(w.Days(9), o.Loc), kind: "success", title: "Audit log verified",
			detail: "Every audit event's hash chain checked out: no gaps and no edits.", href: "/security/audit-logs", security: true})
	}
}

// planName is a plan code as the console names it.
func planName(plan string) string {
	switch plan {
	case "starter":
		return "Starter"
	case "pro":
		return "Pro"
	case "enterprise":
		return "Enterprise"
	}
	return "Free"
}

// notesFor is everything p was notified of in the last three weeks.
func (s *seeder) notesFor(p *world.Person) []note {
	w, o := s.w, p.Org
	var out []note
	add := func(organization uuid.UUID, e event) { out = append(out, note{organization, e}) }
	since := w.Now.Add(-inbox)
	if p.Joined.After(since) {
		since = p.Joined
	}

	// Their own account.
	where := func(d world.Device) string { return d.Label + " · " + d.City + ", " + d.Country }
	add(o.ID, event{at: w.WorkHours(w.Between(since, w.Days(1)), p.Loc), kind: "info", title: "New sign-in to your account",
		detail: where(p.Device) + ". If this wasn't you, sign that session out and change your password.", href: "/account/sessions"})
	add(o.ID, event{at: w.Between(since, w.Days(0.5)), kind: "info", title: "New sign-in from a phone",
		detail: where(p.Mobile) + ".", href: "/account/sessions"})
	if !p.MFASince.IsZero() && p.MFASince.After(since) {
		if p.HasFactor("passkey") {
			add(o.ID, event{at: p.MFASince.Add(-3 * time.Minute), kind: "success", title: "Passkey added",
				detail: "You can now sign in with a passkey instead of a password.", href: "/account/security"})
		}
		if p.HasFactor("totp") {
			add(o.ID, event{at: p.MFASince, kind: "success", title: "Authenticator app set up",
				detail: "Signing in now asks for a code from your authenticator app. Keep your recovery codes somewhere safe.", href: "/account/security"})
		}
	}
	if e := s.enrol; e != nil && e.person == p {
		add(o.ID, event{at: e.at.Add(time.Minute), kind: "alert", title: "Set up a second factor",
			detail: e.by.Name() + " requires you to use MFA. You'll set up an authenticator app the next time you sign in.", href: "/account/security"})
	} else if len(p.MFA) == 0 && o.Spec.Features.MFA == "optional" && p.Role != world.RoleOwner {
		add(o.ID, event{at: w.WorkHours(w.Between(since, w.Days(2)), p.Loc), kind: "warning", title: "Protect your account",
			detail: "Add an authenticator app or a passkey so a stolen password alone can't open your account.", href: "/account/security"})
	}
	for _, g := range p.GuestOf {
		if g.Since.After(since) {
			add(g.Org.ID, event{at: g.Since.Add(time.Minute), kind: "info", title: "You joined " + g.Org.Spec.Name,
				detail: "Switch to it from the organisation menu.", href: "/select-organization"})
		}
	}

	// What happened in the organizations they help run.
	orgs := []struct {
		o    *world.Org
		role string
	}{{o, p.Role}}
	for _, g := range p.GuestOf {
		orgs = append(orgs, struct {
			o    *world.Org
			role string
		}{g.Org, g.Role})
	}
	for _, m := range orgs {
		admin := m.role == world.RoleOwner || m.role == world.RoleAdmin || m.role == world.RoleITAdmin
		for _, e := range s.events[m.o.ID] {
			if admin || (e.billing && m.role == world.RoleBilling) || (e.helpdesk && m.role == world.RoleHelpdesk) ||
				(e.security && (m.role == world.RoleSecurity || m.role == world.RoleAuditor)) {
				add(m.o.ID, e)
			}
		}
	}

	kept := out[:0]
	for _, n := range out {
		if n.at.After(since) && n.at.Before(w.Now.Add(-time.Minute)) {
			kept = append(kept, n)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].at.Before(kept[j].at) })
	if len(kept) > 12 {
		kept = kept[len(kept)-12:]
	}
	return kept
}

// deliver writes p's notifications in order through the notification
// service, with the moments p opened the bell (marking everything read) in
// between: one partway through and one before the newest two, which are
// unread. Some people had read everything.
func (s *seeder) deliver(p *world.Person, notes []note) {
	w := s.w
	svc := w.Deps.Notification.Service
	n := len(notes)
	var reads []time.Time
	switch {
	case n >= 2 && w.Chance(0.2):
		reads = append(reads, w.Between(notes[n-1].at, w.Now.Add(-time.Hour)))
	case n >= 3:
		reads = append(reads, w.Between(notes[n-3].at, notes[n-2].at))
	case n == 2:
		reads = append(reads, w.Between(notes[0].at, notes[1].at))
	}
	if n >= 6 {
		reads = append([]time.Time{w.Between(notes[1].at, notes[n/2].at)}, reads...)
	}
	read := func(t time.Time) {
		w.At(t, func() { w.Check(svc.MarkAllRead(w.Ctx, p.ID), "read notifications of "+p.Email) })
	}
	for _, note := range notes {
		for len(reads) > 0 && reads[0].Before(note.at) {
			read(reads[0])
			reads = reads[1:]
		}
		w.At(note.at, func() {
			w.Check(svc.Notify(w.Ctx, note.organization, p.ID, note.kind, note.title, note.detail, note.href), "notify "+p.Email)
		})
	}
	for _, t := range reads {
		read(t)
	}
}
