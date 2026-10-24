package accounts

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
)

// invitePlan is an invitation that did not (yet) bring someone in.
type invitePlan struct {
	state  string  // pending, expired, revoked or declined
	ago    float64 // days since it was sent
	role   string
	email  string // an existing account's address, for a declined one
	domain string // the invitee's domain when not the organisation's own
}

// invitePlans are each organisation's open and closed invitations. Vertex,
// nine days into its trial, still has most of its team to bring in; one of
// Lumen's lapses tomorrow. Free organisations stay inside five seats.
var invitePlans = map[string][]invitePlan{
	"qeet": {
		{state: "pending", ago: 3.2, role: world.RoleDeveloper},
		{state: "pending", ago: 0.3, role: world.RoleMember},
		{state: "expired", ago: 41, role: world.RoleHelpdesk},
		{state: "revoked", ago: 12, role: world.RoleMember},
	},
	"northwind": {
		{state: "pending", ago: 5, role: world.RoleAuditor, domain: "sharmaandrao-ca.in"},
		{state: "expired", ago: 64, role: world.RoleAuditor, domain: "sharmaandrao-ca.in"},
		{state: "declined", ago: 33, role: world.RoleDeveloper, email: "rohan@qeet.in"},
	},
	"meridian": {
		{state: "pending", ago: 2.4, role: world.RoleAuditor, domain: "hipaa-assurance-partners.us"},
		{state: "revoked", ago: 19, role: world.RoleHelpdesk},
	},
	"lumen": {
		{state: "pending", ago: 13.2, role: world.RoleDeveloper},
		{state: "pending", ago: 4, role: world.RoleMember},
		{state: "expired", ago: 31, role: world.RoleMember},
		{state: "declined", ago: 22, role: world.RoleDeveloper, email: "diego@qeet.in"},
	},
	"aster": {
		{state: "pending", ago: 6, role: world.RoleMember},
		{state: "expired", ago: 26, role: world.RoleHelpdesk},
		{state: "declined", ago: 17, role: world.RoleDeveloper, email: "ananya@qeet.in"},
	},
	"vertex": {
		{state: "pending", ago: 7.8, role: world.RoleMember},
		{state: "pending", ago: 6.9, role: world.RoleMember},
		{state: "pending", ago: 5.1, role: world.RoleBilling},
		{state: "pending", ago: 2.2, role: world.RoleMember},
		{state: "pending", ago: 0.4, role: world.RoleMember},
		{state: "revoked", ago: 6.2, role: world.RoleMember},
	},
	"kestrel": {
		{state: "pending", ago: 9, role: world.RoleMember},
		{state: "expired", ago: 52, role: world.RoleMember},
	},
	"cobalt": {{state: "expired", ago: 71, role: world.RoleOwner}},
	"fjord":  {{state: "pending", ago: 1.5, role: world.RoleOwner}, {state: "pending", ago: 0.8, role: world.RoleOwner}},
}

// acceptedShare is the share of each organisation's directly added people who
// came in by accepting an invitation (the rest were added by an administrator
// or provisioned).
var acceptedShare = map[string]float64{
	"qeet": 0.4, "lumen": 0.5, "aster": 0.6, "vertex": 1, "kestrel": 0.6, "cobalt": 1,
}

// invitations writes each organisation's invitations: the accepted ones its
// people joined through, and pending, expired, revoked and declined ones.
func (s *seeder) invitations(o *world.Org) {
	w := s.w
	svc := w.Deps.Invite.Service
	ctx := w.Ctx

	// Accepted: sent a few hours to a few days before the person joined, and
	// accepted the moment their account was created.
	share := acceptedShare[o.Spec.Slug]
	for _, p := range o.People {
		if p == o.Owner || p.Provisioned != "" || !w.Chance(share) {
			continue
		}
		sent := p.Joined.Add(-time.Duration(2+w.Rand.IntN(70)) * time.Hour)
		if sent.Before(o.Spec.Since.Add(time.Hour)) {
			sent = o.Spec.Since.Add(time.Hour)
		}
		if !sent.Before(p.Joined.Add(-10 * time.Minute)) {
			continue
		}
		inviter := by(o, sent, world.RoleITAdmin, world.RoleAdmin)
		role := o.Roles[p.Role]
		var id uuid.UUID
		w.At(sent, func() {
			iv, token, err := svc.Create(ctx, invite.CreateInput{TenantID: o.ID, Email: p.Email, RoleID: &role}, inviter.Actor())
			w.Check(err, "invite "+p.Email)
			_, err = svc.AcceptAuthenticated(ctx, p.ID, token, p.Actor())
			w.Check(err, "accept invitation as "+p.Email)
			id = iv.ID
		})
		w.Exec("accepted "+p.Email, `UPDATE tenant.invites SET accepted_at = $3, expires_at = created_at + interval '14 days'
			WHERE id = $1 AND tenant_id = $2`, id, o.ID, p.Joined)
		if p.Joined.After(w.Days(21)) {
			s.tell(o, event{at: p.Joined.Add(time.Minute), kind: "success", title: p.Name() + " joined " + o.Spec.Name,
				detail: fmt.Sprintf("%s accepted the invitation and joined as %s.", p.Email, roleName(p.Role)),
				href:   "/users/" + p.ID.String(), helpdesk: true})
		}
	}

	// Pending, expired, revoked and declined.
	for i, plan := range invitePlans[o.Spec.Slug] {
		sent := clamp(w, w.Days(plan.ago))
		if plan.ago >= 1 && plan.ago < 13 {
			sent = clamp(w, w.WorkHours(sent, o.Loc))
		}
		sent = after(sent, o.Spec.Since.Add(time.Hour))
		email := plan.email
		var invitee *world.Person
		if email != "" {
			invitee = s.person(email)
		} else {
			email = s.newcomer(o, plan.domain)
		}
		role, ok := o.Roles[plan.role]
		if !ok {
			role, ok = o.Roles[world.RoleMember]
		}
		if !ok {
			role = o.Roles[world.RoleOwner]
		}
		inviter := by(o, sent, world.RoleITAdmin, world.RoleAdmin)
		var token string
		var id uuid.UUID
		w.At(sent, func() {
			iv, raw, err := svc.Create(ctx, invite.CreateInput{TenantID: o.ID, Email: email, RoleID: &role}, inviter.Actor())
			w.Check(err, "invite "+email+" to "+o.Spec.Slug)
			id, token = iv.ID, raw
			switch plan.state {
			case "revoked":
				w.Check(svc.Revoke(ctx, o.ID, iv.ID, inviter.Actor()), "revoke invitation "+email)
			case "declined":
				w.Check(svc.DeclineForUser(ctx, invitee.ID, iv.ID, invitee.Actor()), "decline invitation as "+email)
			}
		})
		// The service set the expiry from the clock, which At doesn't move.
		w.Exec("expiry of invitation "+email, `UPDATE tenant.invites SET expires_at = created_at + interval '14 days'
			WHERE id = $1 AND tenant_id = $2`, id, o.ID)
		switch plan.state {
		case "expired":
			// Opened after it lapsed, which marks it expired.
			w.Exec("expire invitation "+email, `UPDATE tenant.invites SET status = 'expired' WHERE id = $1 AND tenant_id = $2`, id, o.ID)
		case "pending":
			link := w.Cfg.AppBaseURL + "/invite/accept?token=" + token
			if left := sent.Add(14 * 24 * time.Hour).Sub(w.Now); left < 24*time.Hour {
				s.tell(o, event{at: clamp(w, w.Days(0.2)), kind: "warning", title: "Invitation expires tomorrow",
					detail: fmt.Sprintf("The invitation to %s lapses in %d hours. Resend it to give them another 14 days.", email, int(left.Hours())),
					href:   "/invitations", helpdesk: true})
				s.links = append(s.links, fmt.Sprintf("%-40s %-20s expires in %dh  %s", email, o.Spec.Name, int(left.Hours()), link))
			} else if (o.Spec.Slug == "vertex" && i == 4) || (o.Spec.Slug == "fjord" && i == 0) {
				s.links = append(s.links, fmt.Sprintf("%-40s %-20s %-15s %s", email, o.Spec.Name, roleName(plan.role), link))
			}
		}
	}
}

// person is the seeded person with email, in any organisation.
func (s *seeder) person(email string) *world.Person {
	for _, o := range s.w.Orgs {
		if p := o.Person(email); p != nil {
			return p
		}
	}
	panic("seed: nobody has the address " + email)
}

// invited is every address the seed has invited someone new at.
var invited = map[string]bool{}

// newcomer returns an unused first.last address for someone joining o, at
// domain or, when domain is empty, at the organisation's own.
func (s *seeder) newcomer(o *world.Org, domain string) string {
	w := s.w
	if domain == "" {
		domain = o.Spec.Domain
	}
	for {
		l := world.Pick(w, o.Spec.Locales)
		email := world.EmailLocal(world.Pick(w, l.First), world.Pick(w, l.Last)) + "@" + domain
		if !invited[email] && !s.taken(email) {
			invited[email] = true
			return email
		}
	}
}

// taken reports whether a seeded person already has email.
func (s *seeder) taken(email string) bool {
	for _, o := range s.w.Orgs {
		if o.Person(email) != nil {
			return true
		}
	}
	return false
}

// roleName is a role as the console shows it.
func roleName(role string) string {
	if role == world.RoleOwner {
		return "Owner"
	}
	return strings.TrimSpace(role)
}
