package activity

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

// mail is one email the platform sent through SES, as the delivery records
// keep it (platform.email_messages).
type mail struct {
	id             uuid.UUID
	organization   *uuid.UUID // nil for mail sent for no organization: resets, codes
	to, template   string
	status, reason string
	sent, updated  time.Time
	providerID     string
}

// suppression is an address no mail goes to after a hard bounce or a
// complaint.
type suppression struct {
	id           uuid.UUID
	organization uuid.UUID
	address      string
	reason       string
	detail       string
	message      uuid.UUID
	created      time.Time
	cleared      time.Time
	clearedBy    *world.Person
}

// mail queues an email sent at t; SES reports it delivered seconds later,
// except for the last few minutes', not yet reported.
func (h *history) mail(organization *uuid.UUID, to, template string, t time.Time) *mail {
	w := h.w
	m := &mail{id: uuid.New(), organization: organization, to: to, template: template, status: "delivered", sent: t,
		updated: t.Add(time.Duration(2+w.Rand.IntN(8)) * time.Second), providerID: sesID(w)}
	if t.After(w.Now.Add(-3 * time.Minute)) {
		m.status, m.updated = "sent", t
	}
	h.mails = append(h.mails, m)
	return m
}

// sesID is a message id in Amazon SES's format.
func sesID(w *world.World) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 16)
	for i := range b {
		b[i] = hex[w.Rand.IntN(16)]
	}
	u := uuid.UUID{}
	for i := range u {
		u[i] = byte(w.Rand.IntN(256))
	}
	return "0109019" + string(b[7:]) + "-" + u.String() + "-000000"
}

// mailStories plans the deliveries that went wrong, before the sign-ins are
// generated, since a complaint stops sign-in links to the address that made
// it: an invitation to a mistyped address bounced and the address was
// suppressed; a store worker marked a sign-in link as spam; a mailbox that
// briefly didn't exist was suppressed and then cleared by the owner; a full
// mailbox bounced softly; and a sending-rate limit failed two resets.
// Whoever never verified their address got the code twice.
func (h *history) mailStories() []suppression {
	w := h.w
	var out []suppression
	failed := func(m *mail, status, reason string, after time.Duration) {
		m.status, m.reason, m.updated = status, reason, m.sent.Add(after)
	}
	for _, o := range w.Orgs {
		for _, p := range o.People {
			if p.Unverified {
				h.mail(nil, p.Email, "", p.Joined.Add(40*time.Second))
				if again := p.Joined.Add(49 * time.Hour); again.Before(w.Now) {
					h.mail(nil, p.Email, "", again)
				}
			}
		}
	}
	for _, o := range w.Orgs {
		f := o.Spec.Features
		switch {
		case o == w.Orgs[0]:
			// A mistyped invitation, suppressed; the corrected one arrived.
			var p *world.Person
			for _, q := range o.People {
				if q.Provisioned == "" && q.Login == "" && q.Status == world.StatusActive && q.Joined.After(w.Days(60)) && q.Joined.Before(w.Days(5)) {
					p = q
				}
			}
			if p == nil {
				continue
			}
			typo := mistype(p.Email)
			at := p.Joined.Add(-26 * time.Hour)
			m := h.mail(ptr(o.ID), typo, "invite", at)
			failed(m, "bounced", "Permanent/General: smtp; 550 5.1.1 <"+typo+">: Recipient address rejected: User unknown in virtual mailbox table", 4*time.Second)
			out = append(out, suppression{id: uuid.New(), organization: o.ID, address: typo, reason: "bounce", detail: m.reason, message: m.id, created: m.updated})
			again := h.mail(ptr(o.ID), typo, "invite", at.Add(9*time.Minute))
			again.status, again.reason, again.providerID, again.updated = "suppressed", "address suppressed after a bounce", "", again.sent
			h.mail(ptr(o.ID), p.Email, "invite", at.Add(21*time.Minute))
			// A full mailbox: a soft bounce, nothing suppressed.
			if q := someone(w, o, func(q *world.Person) bool { return q.Provisioned == "" }); q != nil && f.MagicLink {
				m := h.mail(ptr(o.ID), q.Email, "magic_link", h.workTime(q, w.Days(16)))
				failed(m, "bounced", "Transient/MailboxFull: smtp; 452 4.2.2 The email account that you tried to reach is over quota", 40*time.Second)
			}
		case f.MagicLink && len(f.Social) > 0 && o.Spec.Country == "IN" && len(o.People) >= 12:
			// A store worker reported a sign-in link as spam; links stopped.
			p := someone(w, o, func(q *world.Person) bool { return q.Department == "Warehouse" })
			if p == nil {
				continue
			}
			at := h.workTime(p, w.Days(19))
			h.audit(at.Add(-time.Second), audit.Event{OrganizationID: ptr(o.ID), ActorType: "anonymous", Action: "auth.magic_link_requested",
				ResourceType: "user", ResourceID: ptr(p.ID), IP: p.Mobile.IP, UserAgent: p.Mobile.UserAgent,
				Metadata: map[string]any{"app": "hosted_login"}})
			m := h.mail(ptr(o.ID), p.Email, "magic_link", at)
			failed(m, "complained", "abuse", 3*time.Hour)
			out = append(out, suppression{id: uuid.New(), organization: o.ID, address: p.Email, reason: "complaint", detail: "abuse", message: m.id, created: m.updated})
			h.noMagic[p] = window{from: at}
		case f.MagicLink && f.SelfSignup:
			// A mailbox missing during a Google Workspace migration; the owner
			// cleared the suppression two days later.
			p := someone(w, o, func(q *world.Person) bool { return q.Joined.Before(w.Days(40)) })
			if p == nil {
				continue
			}
			at := h.workTime(p, w.Days(27))
			m := h.mail(ptr(o.ID), p.Email, "magic_link", at)
			failed(m, "bounced", "Permanent/General: smtp; 550 5.1.1 The email account that you tried to reach does not exist", 3*time.Second)
			sup := suppression{id: uuid.New(), organization: o.ID, address: p.Email, reason: "bounce", detail: m.reason, message: m.id,
				created: m.updated, cleared: h.workDayAfter(o.Owner, at.Add(24*time.Hour)), clearedBy: o.Owner}
			out = append(out, sup)
			h.noMagic[p] = window{from: at, to: sup.cleared}
			h.audit(sup.cleared, audit.Event{OrganizationID: ptr(o.ID), ActorUserID: ptr(o.Owner.ID), ActorType: "user",
				Action: "email.suppression_cleared", ResourceType: "email_suppression", ResourceID: ptr(sup.id),
				IP: officeIP(o.Owner), UserAgent: o.Owner.Device.UserAgent, RequestID: h.requestID(),
				Metadata: map[string]any{"address": delivery.Hint(p.Email), "reason": "bounce"}})
		case o.Spec.Features.SCIM && o.Spec.Country == "IN":
			// SES throttled two password-reset emails in one burst.
			at := w.Days(33)
			for range 2 {
				if p := someone(w, o, func(q *world.Person) bool { return q.Provisioned == "" || q == o.Owner }); p != nil {
					m := h.mail(nil, p.Email, "", at)
					m.status, m.reason, m.providerID, m.updated = "failed", "Throttling: Maximum sending rate exceeded.", "", at
				}
				at = at.Add(1200 * time.Millisecond)
			}
		}
	}
	return out
}

// someone is an active member of o, other than a test account, matching ok.
func someone(w *world.World, o *world.Org, ok func(*world.Person) bool) *world.Person {
	var c []*world.Person
	for _, p := range o.People {
		if p.Status == world.StatusActive && p.Login == "" && !p.Unverified && !automation(p) && ok(p) {
			c = append(c, p)
		}
	}
	if len(c) == 0 {
		return nil
	}
	return world.Pick(w, c)
}

// mistype drops a letter from the last name of an address.
func mistype(email string) string {
	local, domain, _ := strings.Cut(email, "@")
	if i := strings.IndexByte(local, '.'); i > 0 && len(local) > i+3 {
		local = local[:i+2] + local[i+3:]
	}
	return fmt.Sprintf("%s@%s", local, domain)
}
