package integrations

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	agent "github.com/qeetgroup/qeet-id-server/internal/developer/agents"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
)

// agentSpec is an AI agent: the person accountable for it, who registered it,
// and where its life has gone since.
type agentSpec struct {
	name    string
	scopes  []string
	ttl     int // token lifetime, seconds
	sponsor []who
	by      []who
	created float64
	// end is "suspended" or "decommissioned", ended days ago by whoever
	// manages the organisation's agents.
	end   string
	ended float64
}

// agentSpecs are each organisation's AI agents.
var agentSpecs = map[string][]agentSpec{
	"qeet": {
		{name: "Onboarding Buddy (pilot)", scopes: []string{"user.read", "vault:slack"}, ttl: 600,
			sponsor: []who{title("People Partner"), email("vikram@qeet.in")}, by: []who{email("rohan@qeet.in")}, created: 210, end: "decommissioned", ended: 92},
		{name: "Support Copilot", scopes: []string{"user.read", "vault:zendesk", "vault:slack"}, ttl: 900,
			sponsor: []who{email("sneha@qeet.in")}, by: []who{email("rohan@qeet.in")}, created: 120},
		{name: "Sales Research Agent", scopes: []string{"vault:hubspot", "vault:google-drive"}, ttl: 1800,
			sponsor: []who{title("VP Sales"), dept("Sales")}, by: []who{email("rohan@qeet.in")}, created: 100, end: "suspended", ended: 12},
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:slack"}, ttl: 600,
			sponsor: []who{email("grace@qeet.in")}, by: []who{email("aarav@qeet.in")}, created: 80},
		{name: "Invoice Triage Agent", scopes: []string{"billing.read", "vault:google-drive"}, ttl: 600,
			sponsor: []who{email("vikram@qeet.in")}, by: []who{email("diego@qeet.in")}, created: 58},
	},
	"northwind": {
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:servicenow"}, ttl: 600,
			sponsor: []who{email("kavya.menon@northwindcapital.in")}, by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, created: 110},
		{name: "Loan Document Triage Agent", scopes: []string{"user.read", "vault:salesforce"}, ttl: 900,
			sponsor: []who{title("Chief Risk Officer"), dept("Credit & Risk")}, by: []who{both(team("Platform Engineering"), builders)}, created: 150},
		{name: "Collections Reminder Agent", scopes: []string{"vault:salesforce"}, ttl: 600,
			sponsor: []who{team("Collections")}, by: []who{both(team("Platform Engineering"), builders)}, created: 90, end: "suspended", ended: 20},
	},
	"meridian": {
		{name: "Clinical Scheduling Bot", scopes: []string{"user.read"}, ttl: 600,
			sponsor: []who{title("Chief Nursing Officer"), dept("Clinical Operations")}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 200, end: "decommissioned", ended: 45},
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:servicenow"}, ttl: 600,
			sponsor: []who{email("marcus.brooks@meridianhealth.us")}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 140},
		{name: "Prior Authorization Assistant", scopes: []string{"user.read"}, ttl: 900,
			sponsor: []who{title("Director of Revenue Cycle"), dept("Revenue Cycle")}, by: []who{both(dept("Security"), builders)}, created: 75},
	},
	"lumen": {
		{name: "Docs Q&A Agent", scopes: []string{"vault:github", "vault:linear"}, ttl: 900,
			sponsor: []who{title("Head of DevRel"), dept("Developer Relations")}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 120},
		{name: "Support Copilot", scopes: []string{"user.read", "vault:slack", "vault:linear"}, ttl: 900,
			sponsor: []who{email("jonas.becker@lumenlabshq.dev")}, by: []who{both(team("Core Platform"), builders)}, created: 60},
		{name: "Changelog Writer", scopes: []string{"vault:github", "vault:slack"}, ttl: 600,
			sponsor: []who{email("lucia.garcia@lumenlabshq.dev")}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 40, end: "suspended", ended: 3},
	},
	"aster": {
		{name: "Order Status Agent", scopes: []string{"user.read"}, ttl: 600,
			sponsor: []who{title("Customer Care Manager"), dept("Customer Care")}, by: []who{email("meera.shetty@asterretail.in")}, created: 50},
	},
}

// agents registers the organisation's AI agents with their sponsors, then
// suspends or decommissions the ones whose story ends that way.
func (d *dev) agents(o *world.Org) {
	w := d.w
	for _, s := range agentSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := d.issuer(o, at, s.scopes, s.by...)
		sponsor := person(o, at, s.sponsor...)
		at = d.when(o, days, by, sponsor)
		var a *agent.Agent
		w.At(at, func() {
			var err error
			a, err = w.Deps.Agent.Service.Create(w.Ctx, o.ID, s.name, s.scopes, s.ttl, sponsor.ID, d.as(by))
			w.Check(err, "agent "+s.name)
		})
		if s.end == "" {
			continue
		}
		et := d.when(o, s.ended, by)
		ender := person(o, et, both(dept("Security"), guardians), both(dept("Information Security"), guardians), email(by.Email))
		w.At(et, func() {
			_, err := w.Deps.Agent.Service.Transition(w.Ctx, a.ID, o.ID, s.end, d.as(ender))
			w.Check(err, s.end+" agent "+s.name)
		})
	}
}

// credentialSpec is a run of verifiable credentials of one type, issued to
// people matching to, ttl days long.
type credentialSpec struct {
	typ    string
	to     who
	max    int
	issued float64 // days ago the run was issued
	ttl    float64 // days; 0 never expires
	claims func(p *world.Person) map[string]any
	// revoke revokes one: the credential of someone who left, or else the
	// first issued.
	revoke bool
}

// credentialSpecs are each organisation's verifiable credentials.
var credentialSpecs = map[string][]credentialSpec{
	"qeet": {
		{typ: "EmployeeCredential", to: func(*world.Person) bool { return true }, max: 9, issued: 150, ttl: 365, claims: employee("Qeet Group"), revoke: true},
		{typ: "BuildingAccessCredential", to: dept("Sales"), max: 2, issued: 130, ttl: 120, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "site": "Qeet Group, HSR Layout, Bengaluru", "access_level": "office-hours", "badge": "QB-" + p.EmployeeID[4:]}
		}},
	},
	"northwind": {
		{typ: "EmployeeCredential", to: dept("Credit & Risk"), max: 5, issued: 200, ttl: 365, claims: employee("Northwind Capital"), revoke: true},
		{typ: "AMLTrainingCredential", to: dept("Loan Operations"), max: 4, issued: 300, ttl: 365, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "course": "PMLA & KYC refresher", "score": 80 + len(p.Last)%20}
		}},
	},
	"meridian": {
		{typ: "NursingLicenseCredential", to: title("Nurse"), max: 5, issued: 230, ttl: 700, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "license_number": "RN" + p.EmployeeID[4:] + "7", "jurisdiction": "Massachusetts Board of Registration in Nursing", "license_type": "Registered Nurse"}
		}, revoke: true},
		{typ: "HIPAATrainingCredential", to: dept("Revenue Cycle"), max: 3, issued: 260, ttl: 251, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "course": "HIPAA Privacy & Security 2026", "completed": true}
		}},
	},
	"lumen": {
		{typ: "EmployeeCredential", to: dept("Developer Relations"), max: 3, issued: 100, ttl: 365, claims: employee("Lumen Labs GmbH")},
	},
}

// employee is the claims of an employment credential from employer.
func employee(employer string) func(p *world.Person) map[string]any {
	return func(p *world.Person) map[string]any {
		return map[string]any{"name": p.Name(), "email": p.Email, "employer": employer, "title": p.Title,
			"department": p.Department, "employee_id": p.EmployeeID, "start_date": p.Joined.Format("2006-01-02")}
	}
}

// credentials issues the organisation's verifiable credentials; some have
// expired since. Where a holder left, theirs is revoked the day they went;
// otherwise one is revoked after its holder lost their laptop, and re-issued.
func (d *dev) credentials(o *world.Org) {
	w := d.w
	for _, s := range credentialSpecs[o.Spec.Slug] {
		at := d.when(o, s.issued)
		issuer := person(o, at, both(dept("Security"), guardians), both(dept("Information Security"), guardians), role(world.RoleAdmin))
		at = d.when(o, s.issued, issuer)
		var to []*world.Person
		var gone *world.Person
		for _, p := range o.People {
			if p.ID == uuid.Nil || !s.to(p) || !p.Joined.Before(at) || (p.Status == world.StatusDeleted && !p.Since.After(at)) {
				continue
			}
			if s.revoke && gone == nil && p.Status == world.StatusDeleted {
				gone = p
				to = append([]*world.Person{p}, to...)
			} else {
				to = append(to, p)
			}
		}
		to = to[:min(len(to), s.max)]
		if len(to) == 0 {
			continue
		}
		ids := map[*world.Person]uuid.UUID{}
		w.At(at, func() {
			for _, p := range to {
				ids[p] = d.issue(o, p, s, issuer)
			}
		})
		for _, id := range ids {
			d.expire(o, id, s.ttl)
		}
		if !s.revoke {
			continue
		}
		rt := d.when(o, s.issued/3, issuer)
		lost := gone == nil
		if lost {
			gone = to[len(to)-1]
		} else {
			rt = gone.Since.Add(2 * time.Hour)
		}
		w.At(rt, func() {
			w.Check(w.Deps.VC.Service.Revoke(w.Ctx, ids[gone], o.ID, d.as(issuer)), fmt.Sprintf("revoke %s of %s", s.typ, gone.Email))
		})
		if lost {
			var id uuid.UUID
			w.At(rt.Add(20*time.Minute), func() { id = d.issue(o, gone, s, issuer) })
			d.expire(o, id, s.ttl)
		}
	}
}

// issue issues s's credential to p and returns its id. Someone who has left
// since is no longer a member the service would name, so the credential is
// linked to them directly, as it was when it was issued.
func (d *dev) issue(o *world.Org, p *world.Person, s credentialSpec, issuer *world.Person) uuid.UUID {
	w := d.w
	in := vc.IssueInput{
		Subject:    "did:web:" + o.Spec.Domain + ":people:" + strings.ToLower(p.EmployeeID),
		Type:       s.typ,
		Claims:     s.claims(p),
		TTLSeconds: int(s.ttl * 86400),
	}
	left := p.Status == world.StatusDeleted
	if !left {
		in.UserID = &p.ID
	}
	res, err := w.Deps.VC.Service.Issue(w.Ctx, o.ID, in, d.as(issuer))
	w.Check(err, "credential "+s.typ)
	if left {
		_, err := w.Admin.Exec(w.Ctx, `UPDATE auth.credentials SET user_id = $3 WHERE id = $1 AND tenant_id = $2`, res.CredentialID, o.ID, p.ID)
		w.Check(err, "link credential "+s.typ)
	}
	return res.CredentialID
}

// expire dates credential id's expiry ttl days from when it was issued, in its
// audit record too: the service dates it from the real clock, which At
// doesn't move.
func (d *dev) expire(o *world.Org, id uuid.UUID, ttl float64) {
	if ttl <= 0 {
		return
	}
	w := d.w
	w.Exec("credential expiry", `UPDATE auth.credentials SET expires_at = issued_at + $3 WHERE id = $1 AND tenant_id = $2`,
		id, o.ID, time.Duration(ttl*float64(24*time.Hour)))
	w.Exec("credential expiry in audit", `
		UPDATE audit.events e SET metadata = jsonb_set(e.metadata, '{expires_at}', to_jsonb(c.expires_at))
		FROM auth.credentials c
		WHERE c.id = $1 AND c.tenant_id = $2 AND e.tenant_id = $2 AND e.resource_id = $1 AND e.action = 'credential.issued'`,
		id, o.ID)
}
