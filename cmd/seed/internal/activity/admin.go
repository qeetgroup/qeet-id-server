package activity

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// adminChanges carries out administrators' everyday changes through the
// API's services, each leaving the directory as the census left it: someone
// given an extra role for a few days and then losing it again, someone put in
// the wrong team and taken out minutes later. Directory sync updates from the
// identity provider are recorded as SCIM records them.
func (h *history) adminChanges() {
	for _, o := range h.w.Orgs {
		if !o.Has("starter") || len(o.People) < 12 {
			continue
		}
		h.elevations(o)
		h.teamFix(o)
		h.scimSyncs(o)
	}
}

// actorOf is p acting from their office, in a request of its own.
func (h *history) actorOf(p *world.Person) audit.Actor {
	return audit.Actor{UserID: &p.ID, Type: "user", IP: officeIP(p), UserAgent: p.Device.UserAgent, RequestID: h.requestID()}
}

// elevations gives one or two people a role they don't hold for a few days,
// as cover or for an investigation, then takes it away.
func (h *history) elevations(o *world.Org) {
	w := h.w
	n := 1
	if len(o.People) >= 40 {
		n = 2
	}
	for range n {
		p := someone(w, o, func(q *world.Person) bool { return !isAdmin(q) && q.Joined.Before(w.Days(45)) })
		if p == nil {
			return
		}
		var role string
		for _, r := range []string{world.RoleSecurity, world.RoleHelpdesk, world.RoleITAdmin, world.RoleAuditor} {
			if _, ok := o.Roles[r]; ok && r != p.Role {
				role = r
				break
			}
		}
		if role == "" {
			return
		}
		from := h.workTime(p, w.Between(w.Days(70), w.Days(10)))
		by := actorAt(o, from, world.RoleITAdmin, world.RoleAdmin)
		if by == nil || by == p {
			continue
		}
		until := h.workDayAfter(p, from.Add(time.Duration(1+w.Rand.IntN(4))*24*time.Hour))
		w.At(from, func() {
			w.Check(w.Deps.RBAC.Service.AssignRole(w.Ctx, p.ID, o.ID, o.Roles[role], &by.ID, h.actorOf(by)), "lend "+role+" to "+p.Email)
		})
		w.At(until, func() {
			w.Check(w.Deps.RBAC.Service.UnassignRole(w.Ctx, p.ID, o.ID, o.Roles[role], h.actorOf(by)), "take "+role+" back from "+p.Email)
		})
	}
}

// teamFix puts someone in the wrong team this week, and takes them out again
// a few minutes later.
func (h *history) teamFix(o *world.Org) {
	w := h.w
	p := someone(w, o, func(q *world.Person) bool { return q.Team != "" && q.Joined.Before(w.Days(20)) })
	if p == nil {
		return
	}
	var teams []string
	for _, d := range o.Spec.Depts {
		for _, t := range d.Teams {
			if _, ok := o.Groups[t]; ok && t != p.Team {
				teams = append(teams, t)
			}
		}
	}
	if len(teams) == 0 {
		return
	}
	group := o.Groups[world.Pick(w, teams)]
	at := h.workTime(p, w.Between(w.Days(4), w.Days(1)))
	by := actorAt(o, at, world.RoleITAdmin, world.RoleAdmin)
	if by == nil || by == p {
		return
	}
	w.At(at, func() {
		w.Check(w.Deps.Group.Service.AddMember(w.Ctx, group, p.ID, o.ID, h.actorOf(by)), "misplace "+p.Email)
	})
	w.At(at.Add(jitter(w, 4, 15)), func() {
		w.Check(w.Deps.Group.Service.RemoveMember(w.Ctx, group, p.ID, o.ID, h.actorOf(by)), "correct "+p.Email)
	})
}

// scimSyncs records the identity provider pushing profile updates for
// people it provisions: a SCIM PUT carries active=true, which SCIM records.
func (h *history) scimSyncs(o *world.Org) {
	w := h.w
	if !o.Spec.Features.SCIM {
		return
	}
	ip, ua := "198.51.100.230", "Okta SCIM Client 1.0.0"
	if o.Spec.Features.SSO == "entra" {
		ip, ua = "192.0.2.236", "Azure AD Provisioning Agent"
	}
	for range 6 + w.Rand.IntN(5) {
		p := someone(w, o, func(q *world.Person) bool { return q.Provisioned == "scim" })
		if p == nil {
			return
		}
		at := w.Between(maxTime(p.Joined.Add(24*time.Hour), w.Days(60)), w.Days(0.5))
		h.audit(at, audit.Event{TenantID: ptr(o.ID), ActorType: "scim", Action: "user.updated", ResourceType: "user",
			ResourceID: ptr(p.ID), IP: ip, UserAgent: ua, RequestID: h.requestID(), Metadata: map[string]any{"status": "active"}})
	}
}

// groupProvisioning puts the rows one request wrote under its request id:
// the census created each person, gave them their role and put them in
// their team in one go, but recorded no request.
func groupProvisioning(w *world.World) {
	w.Exec("group provisioning requests", `
		WITH created AS (
			SELECT tenant_id, resource_id AS user_id, created_at, row_number() OVER (ORDER BY created_at, id) AS n
			FROM audit.events
			WHERE action = 'user.created' AND COALESCE(request_id, '') = '' AND tenant_id IS NOT NULL
		)
		UPDATE audit.events e
		SET request_id = 'qeet-id-api-6f9d8c7b5-q4hfj/Tg2sR6yP0m-' || lpad((200000 + c.n)::text, 6, '0')
		FROM created c
		WHERE e.tenant_id = c.tenant_id AND COALESCE(e.request_id, '') = ''
		  AND e.created_at BETWEEN c.created_at AND c.created_at + interval '2 seconds'
		  AND ((e.action IN ('user.created', 'role.assigned') AND e.resource_id = c.user_id)
		       OR (e.action = 'group.member_added' AND e.metadata->>'user_id' = c.user_id::text))`)
}
