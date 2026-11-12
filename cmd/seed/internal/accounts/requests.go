package accounts

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// accessRequest is a person asking for a role, and what became of it.
type accessRequest struct {
	dept, team string // where the requester works
	role       string // the role asked for
	reason     string
	hours      int     // how long for; 0 is for good
	asked      float64 // days ago
	// outcome is pending, approved, denied, cancelled or expired; answered is
	// how many minutes after asking it was approved, denied or cancelled.
	outcome  string
	answered float64
	by, note string // who answered (an email), and what they wrote
}

// accessRequests are the requests each organisation's people made, a few of
// each outcome: the console's queue, a person's own requests, and roles given
// for a while and taken back when the time was up.
var accessRequests = map[string][]accessRequest{
	"qeet": {
		{dept: "Product", role: world.RoleDeveloper, hours: 24, asked: 0.15, outcome: "pending",
			reason: "Reproducing a merchant's failed refund in Qeet Pay: I need the webhook delivery log for their account."},
		{dept: "Trust & Safety", role: world.RoleSecurity, hours: 168, asked: 1.2, outcome: "pending",
			reason: "Investigating a coordinated spam ring on Qeet Circle. I need the sign-in risk events of the staff accounts it touched."},
		{dept: "Security", role: world.RoleAuditor, hours: 72, asked: 1, outcome: "approved", answered: 40, by: "priya@qeet.in",
			reason: "Quarterly access review: reading every role and group assignment before the SOC 2 sample.",
			note:   "Approved for the review window."},
		{dept: "Engineering", team: "Site Reliability", role: world.RoleAdmin, hours: 8, asked: 9, outcome: "approved", answered: 12, by: "aarav@qeet.in",
			reason: "Qeet Notify incident: rotating the webhook signing secrets of every product.",
			note:   "Go ahead. Post in #incidents when the rotation is done."},
		{dept: "Customer Success", team: "Onboarding", role: world.RoleDeveloper, asked: 20, outcome: "approved", answered: 180, by: "aarav@qeet.in",
			reason: "Moving to the Qeet ID integrations team: I build the customer SDK samples now.",
			note:   "Welcome to the team."},
		{dept: "Sales", role: world.RoleBilling, asked: 6, outcome: "denied", answered: 95, by: "vikram@qeet.in",
			reason: "I'd like to see customers' invoices before renewal calls.",
			note:   "Invoices stay with Finance. Ask me for an export of the accounts you're renewing."},
		{dept: "Design", role: world.RoleDeveloper, hours: 48, asked: 3, outcome: "cancelled", answered: 110,
			reason: "Checking how the new Qeetrix sign-in screens render in the Qeet Pay console."},
		{dept: "Customer Success", team: "Support", role: world.RoleAuditor, asked: 25, outcome: "expired",
			reason: "A customer's DPO asked for every change made to their admins' accounts this quarter; I need to read the audit log."},
	},
	"northwind": {
		{dept: "Credit & Risk", role: world.RoleAuditor, hours: 720, asked: 45, outcome: "approved", answered: 65, by: "kavya.menon@northwindcapital.in",
			reason: "RBI inspection: the inspectors asked for the access log of the lending systems.",
			note:   "Approved until the inspection closes."},
		{dept: "Loan Operations", role: world.RoleHelpdesk, hours: 336, asked: 0.5, outcome: "pending",
			reason: "Covering account unlocks for the Pune branch during the festive-season rush."},
	},
	"meridian": {
		{dept: "Revenue Cycle", role: world.RoleITAdmin, asked: 4, outcome: "denied", answered: 50, by: "jennifer.walsh@meridianhealth.us",
			reason: "I'd like to add the new medical coders myself.",
			note:   "Accounts come from Workday through SCIM. Raise a ticket with the Service Desk and they'll be there the next morning."},
		{dept: "Clinical Operations", role: world.RoleHelpdesk, hours: 12, asked: 0.3, outcome: "approved", answered: 20, by: "jennifer.walsh@meridianhealth.us",
			reason: "Night shift: resetting sign-ins for the agency nurses starting tonight.",
			note:   "For tonight only."},
	},
	"lumen": {
		{dept: "Go-to-Market", role: world.RoleDeveloper, hours: 48, asked: 0.8, outcome: "pending",
			reason: "Recording the CLI demo for the launch video."},
	},
}

// accessRequests carries out o's access requests, each on its date, through
// the API's own service: approvers are told, roles are given, and a
// time-limited role is taken back when its time is up, as the scheduler does.
func (s *seeder) accessRequests(o *world.Org) {
	w := s.w
	svc := w.Deps.AccessRequest.Service
	for _, r := range accessRequests[o.Spec.Slug] {
		asked := clamp(w, w.WorkHours(w.Days(r.asked), o.Loc))
		if r.asked < 1 {
			asked = w.Days(r.asked)
		}
		p := asker(o, asked, r.dept, r.team, r.role)
		if p == nil {
			continue
		}
		in := accessrequest.CreateInput{RoleID: o.Roles[r.role], Reason: r.reason}
		if r.hours > 0 {
			hours := r.hours
			in.DurationHours = &hours
		}
		var req *accessrequest.AccessRequest
		w.At(asked, func() {
			var err error
			req, err = svc.Create(w.Ctx, o.ID, p.ID, in, p.Actor())
			w.Check(err, "access request by "+p.Email)
		})
		at := asked.Add(time.Duration(r.answered * float64(time.Minute)))
		approver := o.Person(r.by)
		switch r.outcome {
		case "approved":
			w.At(at, func() {
				_, err := svc.Approve(w.Ctx, o.ID, req.ID, approver.ID, r.note, approver.Actor())
				w.Check(err, "approve the access request of "+p.Email)
			})
			if r.hours > 0 {
				s.endAccess(o, p, req, at.Add(time.Duration(r.hours)*time.Hour))
			}
		case "denied":
			w.At(at, func() {
				_, err := svc.Deny(w.Ctx, o.ID, req.ID, approver.ID, r.note, approver.Actor())
				w.Check(err, "deny the access request of "+p.Email)
			})
		case "cancelled":
			w.At(at, func() {
				w.Check(svc.Cancel(w.Ctx, o.ID, p.ID, req.ID, p.Actor()), "cancel the access request of "+p.Email)
			})
		case "expired":
			s.lapse(o, p, req, asked.Add(accessrequest.PendingFor))
		}
		// The API dates the lapse from now; the story dates it from the asking.
		// Only once it is answered: the API refuses to answer a lapsed request.
		w.Exec("access request expiry", `UPDATE rbac.access_requests SET expires_at = $3 WHERE id = $1 AND tenant_id = $2`,
			req.ID, o.ID, asked.Add(accessrequest.PendingFor))
	}
}

// endAccess dates a time-limited grant to end at ends and, when that has
// passed, takes the role back as the scheduler does then.
func (s *seeder) endAccess(o *world.Org, p *world.Person, req *accessrequest.AccessRequest, ends time.Time) {
	w := s.w
	w.Exec("access request end", `UPDATE rbac.access_requests SET access_ends_at = $3 WHERE id = $1 AND tenant_id = $2`, req.ID, o.ID, ends)
	if ends.After(w.Now) {
		return
	}
	at := ends.Add(time.Duration(1+w.Rand.IntN(4)) * time.Minute)
	system := audit.Actor{Type: "system"}
	w.At(at, func() {
		w.Check(w.Deps.RBAC.Service.UnassignRole(w.Ctx, p.ID, o.ID, req.Role.ID, system), "take back the role of "+p.Email)
		w.Exec("access ended", `UPDATE rbac.access_requests SET ended_at = NOW() WHERE id = $1 AND tenant_id = $2`, req.ID, o.ID)
		w.Check(w.Deps.Notification.Service.Notify(w.Ctx, o.ID, p.ID, "info", "Your time-limited access has ended", "", ""),
			"tell "+p.Email+" their access ended")
	})
	id := req.ID
	w.Audit(at, audit.Event{TenantID: &o.ID, ActorType: "system", Action: "access_request.access_ended", ResourceType: "access_request",
		ResourceID: &id, Metadata: map[string]any{"role_id": req.Role.ID, "requester_id": p.ID}})
}

// lapse expires a request nobody answered, at the end of its wait, as the
// scheduler does.
func (s *seeder) lapse(o *world.Org, p *world.Person, req *accessrequest.AccessRequest, at time.Time) {
	w := s.w
	w.At(at, func() {
		w.Exec("access request lapsed", `UPDATE rbac.access_requests SET status = 'expired' WHERE id = $1 AND tenant_id = $2`, req.ID, o.ID)
		w.Check(w.Deps.Notification.Service.Notify(w.Ctx, o.ID, p.ID, "info", "Your access request expired without an answer", "", ""),
			"tell "+p.Email+" their request expired")
	})
	id := req.ID
	w.Audit(at, audit.Event{TenantID: &o.ID, ActorType: "system", Action: "access_request.expired", ResourceType: "access_request",
		ResourceID: &id, Metadata: map[string]any{"role_id": req.Role.ID, "requester_id": p.ID}})
}

// asker is who in o, in dept (and team, when set), asks for role at t: someone
// there over a fortnight who is still there today, doesn't hold role and isn't a
// test account (whose role would change under the tester).
func asker(o *world.Org, t time.Time, dept, team, role string) *world.Person {
	for _, p := range o.People {
		if p.Department == dept && (team == "" || p.Team == team) && p.Role != role && p.Role != world.RoleOwner &&
			p.Login == "" && p.Status == world.StatusActive && t.Sub(p.Joined) > 14*24*time.Hour {
			return p
		}
	}
	return nil
}
