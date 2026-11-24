// Package accounts seeds each organization's own settings and its people's
// account states: branding, domains, email templates, security, sign-in and
// retention policies, group roles and templates, invitations, suspended and
// deleted accounts, data requests, access requests and notifications.
package accounts

import (
	"fmt"
	"log/slog"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// seeder carries what the step's parts share.
type seeder struct {
	w *world.World
	// dns are the TXT records the organizations published, by name.
	dns published
	// links are pending invitations' accept links, for the summary.
	links []string
}

// Seed applies every organization's settings and account states.
func Seed(w *world.World) {
	// With no mail server the invitation emails are logged, a line each; the
	// summary prints the links worth having.
	defer slog.SetLogLoggerLevel(slog.SetLogLoggerLevel(slog.LevelWarn))
	s := &seeder{w: w, dns: published{}}
	w.Deps.DomainVerify.Service = w.Deps.DomainVerify.Service.WithResolver(s.dns)
	for _, o := range w.Orgs {
		s.branding(o)
		s.domains(o)
		s.policies(o)
		s.templates(o)
		s.groups(o)
		s.invitations(o)
		s.states(o)
		s.dataRequests(o)
		s.accessRequests(o)
	}
	s.enrolmentDemo()
	s.notifications()
	s.summary()
}

// actorOn is who changes target's account: the first person holding one of
// roles whom the server lets act on target (they hold every permission target
// holds), else the owner.
func (s *seeder) actorOn(o *world.Org, target *world.Person, roles ...string) *world.Person {
	for _, role := range roles {
		for _, p := range o.Active() {
			organization, id := o.ID, p.ID
			caller := &httpx.Principal{OrganizationID: &organization, UserID: &id, ActorType: "user"}
			if p.Role == role && p != target && s.w.Deps.User.ActOnCheck(s.w.Ctx, caller, o.ID, target.ID) == nil {
				return p
			}
		}
	}
	return o.Owner
}

// risks is how risky each suspension reason looks to the reviewer.
var risks = map[string]string{"suspicious_activity": "high", "policy_violation": "medium", "offboarding": "low", "inactive": "low"}

// states carries out the account states the census decided through the
// console's own requests: suspensions, reviewed unless the risk is high, and
// deletions. A provisioned account offboarded at the identity provider is
// deactivated over SCIM instead, with the connections.
func (s *seeder) states(o *world.Org) {
	for _, p := range o.People {
		path := "/users/" + p.ID.String()
		switch {
		case p.Status == world.StatusSuspended && (!p.Provisioned || p.Reason != "offboarding"):
			by := s.actorOn(o, p, world.RoleSecurity, world.RoleITAdmin, world.RoleAdmin)
			s.w.API.Do(o, by, "PATCH", path, map[string]any{"status": "suspended"}, nil)
			review := "reviewed"
			if risks[p.Reason] == "high" {
				review = "pending"
			}
			s.w.API.Do(o, by, "PUT", path+"/suspension", map[string]any{"reason": p.Reason, "risk": risks[p.Reason], "review": review}, nil)
		case p.Status == world.StatusDeleted:
			s.w.API.Do(o, s.actorOn(o, p, world.RoleITAdmin, world.RoleAdmin), "DELETE", path, nil, nil)
		}
	}
}

// enrolmentDemo makes one Qeet Group account, with no second factor, required
// to set one up: its next sign-in shows the MFA enrolment screen.
func (s *seeder) enrolmentDemo() {
	o := s.w.Org("qeet")
	for _, dept := range []string{"Sales", "Customer Success", ""} {
		for _, p := range o.Active() {
			if p.Login == "" && len(p.MFA) == 0 && !p.Unverified && p.Role != world.RoleOwner && (dept == "" || p.Department == dept) {
				s.w.API.Do(o, o.Person("priya@qeet.in"), "PUT", "/users/"+p.ID.String()+"/mfa-required", map[string]any{"required": true}, nil)
				p.Login = roleName(p.Role) + " — must set up MFA at next sign-in (QR code + recovery codes)"
				return
			}
		}
	}
}

// invitePlan is an invitation that did not (yet) bring someone in.
type invitePlan struct {
	state  string // pending, revoked or declined
	role   string
	email  string // an existing account's address, for a declined one
	domain string // the invitee's domain when not the organization's own
}

// invitePlans are each organization's open and closed invitations. Vertex,
// on its trial, still has most of its team to bring in. Free organizations
// stay inside five seats.
var invitePlans = map[string][]invitePlan{
	"qeet":      {{state: "pending", role: world.RoleDeveloper}, {state: "pending", role: world.RoleMember}, {state: "revoked", role: world.RoleMember}},
	"northwind": {{state: "pending", role: world.RoleAuditor, domain: "sharmaandrao-ca.in"}, {state: "declined", role: world.RoleDeveloper, email: "rohan@qeet.in"}},
	"meridian":  {{state: "pending", role: world.RoleAuditor, domain: "hipaa-assurance-partners.us"}, {state: "revoked", role: world.RoleHelpdesk}},
	"lumen": {{state: "pending", role: world.RoleDeveloper}, {state: "pending", role: world.RoleMember},
		{state: "declined", role: world.RoleDeveloper, email: "diego@qeet.in"}},
	"aster": {{state: "pending", role: world.RoleMember}, {state: "declined", role: world.RoleDeveloper, email: "ananya@qeet.in"}},
	"vertex": {{state: "pending", role: world.RoleMember}, {state: "pending", role: world.RoleMember}, {state: "pending", role: world.RoleBilling},
		{state: "pending", role: world.RoleMember}, {state: "revoked", role: world.RoleMember}},
	"kestrel": {{state: "pending", role: world.RoleMember}},
	"fjord":   {{state: "pending", role: world.RoleOwner}, {state: "pending", role: world.RoleOwner}},
}

// invited is every address the seed has invited someone new at.
var invited = map[string]bool{}

// invitations sends each organization's open and closed invitations through
// the invitation service; Vertex's and Fjord's last pending ones go in the
// summary, for a tester to accept.
func (s *seeder) invitations(o *world.Org) {
	w, svc, inviter := s.w, s.w.Deps.Invite.Service, o.Admin()
	var last string
	for _, plan := range invitePlans[o.Spec.Slug] {
		email := plan.email
		for email == "" {
			l, domain := world.Pick(w, o.Spec.Locales), plan.domain
			if domain == "" {
				domain = o.Spec.Domain
			}
			if e := world.EmailLocal(world.Pick(w, l.First), world.Pick(w, l.Last)) + "@" + domain; !invited[e] && w.Person(e) == nil {
				email, invited[e] = e, true
			}
		}
		role, ok := o.Roles[plan.role]
		if !ok {
			role = o.Roles[world.RoleMember]
		}
		iv, token, err := svc.Create(w.Ctx, invite.CreateInput{OrganizationID: o.ID, Email: email, RoleID: &role}, inviter.Actor())
		w.Check(err, "invite "+email+" to "+o.Spec.Slug)
		switch plan.state {
		case "revoked":
			w.Check(svc.Revoke(w.Ctx, o.ID, iv.ID, inviter.Actor()), "revoke invitation "+email)
		case "declined":
			p := w.Person(email)
			w.Check(svc.DeclineForUser(w.Ctx, p.ID, iv.ID, p.Actor()), "decline invitation as "+email)
		default:
			last = fmt.Sprintf("%-40s %-20s %-15s %s/invite/accept?token=%s", email, o.Spec.Name, roleName(plan.role), w.Cfg.AppBaseURL, token)
		}
	}
	if last != "" && (o.Spec.Slug == "vertex" || o.Spec.Slug == "fjord") {
		s.links = append(s.links, last)
	}
}

// roleName is a role as the console shows it.
func roleName(role string) string {
	if role == world.RoleOwner {
		return "Owner"
	}
	return role
}

// erasureReason is why an organization files an erasure request, in its
// jurisdiction's terms.
func erasureReason(o *world.Org) string {
	switch o.Spec.Country {
	case "IN":
		return "Former employee: erasure under the Digital Personal Data Protection Act 2023, s.12"
	case "US":
		return "Offboarded workforce member: erase per the records retention schedule"
	}
	return "Former employee: erasure request under GDPR Art. 17"
}

// dataRequests files the organization's data requests through the GDPR
// service: an erasure request for each leaver, waiting out its grace period;
// one filed in error for an account on legal hold and cancelled; and an
// export of a suspended account's data, which the server's sweeper builds.
func (s *seeder) dataRequests(o *world.Org) {
	w, svc := s.w, s.w.Deps.GDPR.Service()
	by := o.First(world.HasRole(world.RoleAdmin))
	cancelled, exported := false, false
	for _, p := range o.People {
		switch {
		case p.Status == world.StatusDeleted:
			_, err := svc.Request(w.Ctx, gdpr.CreateInput{OrganizationID: o.ID, UserID: p.ID, Reason: erasureReason(o)}, by.Actor())
			w.Check(err, "erasure request for "+p.Email)
		case p.Status == world.StatusSuspended && p.Reason == "policy_violation" && !cancelled:
			req, err := svc.Request(w.Ctx, gdpr.CreateInput{OrganizationID: o.ID, UserID: p.ID,
				Reason: erasureReason(o) + " (filed in error: account on legal hold)"}, by.Actor())
			w.Check(err, "erasure request for "+p.Email)
			w.Check(svc.Cancel(w.Ctx, o.ID, req.ID, by.Actor()), "cancel erasure request for "+p.Email)
			cancelled = true
		case p.Status == world.StatusSuspended && p.Reason == "suspicious_activity" && !exported:
			_, err := svc.RequestExport(w.Ctx, gdpr.ExportInput{OrganizationID: o.ID, UserID: p.ID}, by.Actor())
			w.Check(err, "export request for "+p.Email)
			exported = true
		}
	}
}

// accessRequest is a person asking for a role, and what became of it.
type accessRequest struct {
	dept, team string // where the requester works
	role       string // the role asked for
	reason     string
	hours      int // how long for; 0 is for good
	// outcome is pending, approved, denied or cancelled; by is who answered (an
	// email), and note what they wrote.
	outcome  string
	by, note string
}

// accessRequests are the requests each organization's people made, a few of
// each outcome: the console's queue, a person's own requests, and roles given
// for a while and taken back when the time was up.
var accessRequests = map[string][]accessRequest{
	"qeet": {
		{dept: "Product", role: world.RoleDeveloper, hours: 24, outcome: "pending",
			reason: "Reproducing a merchant's failed refund in Qeet Pay: I need the webhook delivery log for their account."},
		{dept: "Trust & Safety", role: world.RoleSecurity, hours: 168, outcome: "pending",
			reason: "Investigating a coordinated spam ring on Qeet Circle. I need the sign-in risk events of the staff accounts it touched."},
		{dept: "Security", role: world.RoleAuditor, hours: 72, outcome: "approved", by: "priya@qeet.in",
			reason: "Quarterly access review: reading every role and group assignment before the SOC 2 sample.",
			note:   "Approved for the review window."},
		{dept: "Engineering", team: "Site Reliability", role: world.RoleAdmin, hours: 8, outcome: "approved", by: "aarav@qeet.in",
			reason: "Qeet Notify incident: rotating the webhook signing secrets of every product.",
			note:   "Go ahead. Post in #incidents when the rotation is done."},
		{dept: "Customer Success", team: "Onboarding", role: world.RoleDeveloper, outcome: "approved", by: "aarav@qeet.in",
			reason: "Moving to the Qeet ID integrations team: I build the customer SDK samples now.",
			note:   "Welcome to the team."},
		{dept: "Sales", role: world.RoleBilling, outcome: "denied", by: "vikram@qeet.in",
			reason: "I'd like to see customers' invoices before renewal calls.",
			note:   "Invoices stay with Finance. Ask me for an export of the accounts you're renewing."},
		{dept: "Design", role: world.RoleDeveloper, hours: 48, outcome: "cancelled",
			reason: "Checking how the new Qeetrix sign-in screens render in the Qeet Pay console."},
	},
	"northwind": {
		{dept: "Credit & Risk", role: world.RoleAuditor, hours: 720, outcome: "approved", by: "kavya.menon@northwindcapital.in",
			reason: "RBI inspection: the inspectors asked for the access log of the lending systems.",
			note:   "Approved until the inspection closes."},
		{dept: "Loan Operations", role: world.RoleHelpdesk, hours: 336, outcome: "pending",
			reason: "Covering account unlocks for the Pune branch during the festive-season rush."},
	},
	"meridian": {
		{dept: "Revenue Cycle", role: world.RoleITAdmin, outcome: "denied", by: "jennifer.walsh@meridianhealth.us",
			reason: "I'd like to add the new medical coders myself.",
			note:   "Accounts come from Workday through SCIM. Raise a ticket with the Service Desk and they'll be there the next morning."},
		{dept: "Clinical Operations", role: world.RoleHelpdesk, hours: 12, outcome: "approved", by: "jennifer.walsh@meridianhealth.us",
			reason: "Night shift: resetting sign-ins for the agency nurses starting tonight.",
			note:   "For tonight only."},
	},
	"lumen": {
		{dept: "Go-to-Market", role: world.RoleDeveloper, hours: 48, outcome: "pending",
			reason: "Recording the CLI demo for the launch video."},
	},
}

// accessRequests carries out o's access requests through the access request
// service: approvers are told, and approved roles are given.
func (s *seeder) accessRequests(o *world.Org) {
	w, svc := s.w, s.w.Deps.AccessRequest.Service
	for _, r := range accessRequests[o.Spec.Slug] {
		p := o.First(func(p *world.Person) bool {
			return p.Org == o && p.Department == r.dept && (r.team == "" || p.Team == r.team) && p.Role != r.role &&
				p.Role != world.RoleOwner && p.Login == "" && !p.Unverified
		})
		if p == o.Owner {
			continue
		}
		in := accessrequest.CreateInput{RoleID: o.Roles[r.role], Reason: r.reason}
		if r.hours > 0 {
			in.DurationHours = &r.hours
		}
		req, err := svc.Create(w.Ctx, o.ID, p.ID, in, p.Actor())
		w.Check(err, "access request by "+p.Email)
		approver := o.Person(r.by)
		switch r.outcome {
		case "approved":
			_, err = svc.Approve(w.Ctx, o.ID, req.ID, approver.ID, r.note, approver.Actor())
		case "denied":
			_, err = svc.Deny(w.Ctx, o.ID, req.ID, approver.ID, r.note, approver.Actor())
		case "cancelled":
			err = svc.Cancel(w.Ctx, o.ID, p.ID, req.ID, p.Actor())
		}
		w.Check(err, r.outcome+" the access request of "+p.Email)
	}
}

// notifications fills the bell of every owner and test account through the
// notification service: billing and set-up news for those who run an
// organization, and a nudge to anyone without a second factor where it is
// optional. The older ones have been read.
func (s *seeder) notifications() {
	w := s.w
	type note struct{ kind, title, detail, href string }
	for _, o := range w.Orgs {
		var notes []note
		switch o.Spec.Billing {
		case "unpaid":
			notes = append(notes, note{"alert", "Invoice unpaid", "Your " + o.Spec.Plan + " invoice is open. Pay it in Billing to keep the plan's features.", "/settings/billing"})
		case "trialing":
			notes = append(notes, note{"warning", "Your Pro trial ends in 14 days", "Add a payment method to keep SSO, audit export and ABAC after the trial.", "/settings/billing"})
		case "canceled":
			notes = append(notes, note{"info", "Subscription cancelled", "Starter ends with the current period; the organization then moves to Free.", "/settings/billing"})
		}
		for _, d := range domainPlans[o.Spec.Slug] {
			if d.state == "attention" && o.Has("starter") {
				notes = append(notes, note{"warning", "Domain verification failed",
					"We couldn't find the TXT record at _qeet-verification." + d.name + ". Publish the record, then check again.", "/settings/organization/domains"})
			}
		}
		switch o.Spec.Slug {
		case "vertex":
			notes = append(notes, note{"info", "Okta SAML connection saved as a draft", "Test the connection, then activate it to let people sign in with Okta.", "/auth/connections/saml"})
		case "fjord":
			notes = append(notes, note{"success", "Welcome to Qeet ID", "Your organization is ready. Invite your team and connect your first application.", "/"},
				note{"info", "Connect your first application", "Register an OIDC application so your users can sign in with Qeet ID.", "/applications"})
		}
		for _, p := range o.People {
			if p.Status != world.StatusActive || (p.Login == "" && p != o.Owner) {
				continue
			}
			mine := notes
			if p != o.Owner && p.Role != world.RoleAdmin && p.Role != world.RoleBilling {
				mine = nil
			}
			mine = append([]note{{"info", "New sign-in to your account", p.Device.Label + " · " + p.City + ", " + p.Country +
				". If this wasn't you, sign that session out and change your password.", "/account/sessions"}}, mine...)
			if len(p.MFA) == 0 && o.Spec.Features.MFA == "optional" && p.Role != world.RoleOwner {
				mine = append(mine, note{"warning", "Protect your account", "Add an authenticator app or a passkey so a stolen password alone can't open your account.", "/account/security"})
			}
			for i, n := range mine {
				if i == len(mine)-1 && i > 0 {
					w.Check(w.Deps.Notification.Service.MarkAllRead(w.Ctx, p.ID), "read the notifications of "+p.Email)
				}
				w.Check(w.Deps.Notification.Service.Notify(w.Ctx, o.ID, p.ID, n.kind, n.title, n.detail, n.href), "notify "+p.Email)
			}
		}
	}
}

// summary adds the step's notes: invitation links to accept, and where to find
// the settings and account states it seeded.
func (s *seeder) summary() {
	w := s.w
	for _, l := range s.links {
		w.Note("Invitations — open the link signed out; the console's accept page creates the account", "%s", l)
	}
	counts := map[string]int{}
	for _, o := range w.Orgs {
		for _, p := range o.People {
			counts[p.Status]++
			if p.Status == world.StatusSuspended && risks[p.Reason] == "high" {
				counts["pending"]++
			}
		}
	}
	const section = "Organization settings and account states"
	w.Note(section, "Northwind Capital: MFA required, 14-character passwords, 12h sessions / 30m idle, lockout after 3 failures;")
	w.Note(section, "  login domain login.northwindcapital.in and Meridian's sso.meridianhealth.us show DNS pending (Settings → Domains)")
	w.Note(section, "Domains: verified, pending (Vertex, Meridian, Aster) and needing attention (Northwind nwcfinance.in, Lumen)")
	w.Note(section, "Lumen Labs: hosted self-registration on, 15-minute magic links, German invite and magic-link emails")
	w.Note(section, "Kestrel: MFA required with a 14-day grace; Meridian: MFA for administrators with a 7-day grace")
	w.Note(section, "%d suspended accounts (%d awaiting review) and %d deleted, each with a pending erasure request; one cancelled",
		counts[world.StatusSuspended], counts["pending"], counts[world.StatusDeleted])
	w.Note(section, "Access requests pending, approved, denied and cancelled (Qeet Group, Northwind, Meridian, Lumen)")
}
