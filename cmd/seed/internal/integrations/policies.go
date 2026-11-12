package integrations

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// abacSpec is an ABAC policy as first written, and the edits made to it
// since: each edit is a version on the console's history.
type abacSpec struct {
	name, description, effect, resource, action, condition string
	priority                                               int
	enabled                                                bool
	by                                                     []who
	created                                                float64
	edits                                                  []abacEdit
}

// abacEdit changes a policy days ago.
type abacEdit struct {
	days   float64
	change func(*abac.UpdateInput)
}

const (
	// The contractor policies apply only where the caller says who is a
	// contractor and what time it is (an application's access check does; the
	// console's own requests carry neither), so they test that both are known:
	// a deny on an unknown attribute refuses.
	contractorHours = `{"all":[{"attr":"subject.employment_type","op":"exists"},{"attr":"context.hour","op":"exists"},` +
		`{"attr":"subject.employment_type","op":"eq","value":"contractor"},` +
		`{"any":[{"attr":"context.hour","op":"lt","value":9},{"attr":"context.hour","op":"gte","value":18}]}]}`
	contractorHoursWide = `{"all":[{"attr":"subject.employment_type","op":"exists"},{"attr":"context.hour","op":"exists"},` +
		`{"attr":"context.weekday","op":"exists"},{"attr":"subject.employment_type","op":"eq","value":"contractor"},` +
		`{"any":[{"attr":"context.hour","op":"lt","value":8},{"attr":"context.hour","op":"gte","value":20},` +
		`{"attr":"context.weekday","op":"in","value":["Sat","Sun"]}]}]}`
	withoutMFA = `{"not":{"attr":"context.mfa","op":"eq","value":true}}`
)

// outside is a condition true where the request comes from a known country
// not in countries.
func outside(countries ...string) string {
	b, _ := json.Marshal(countries)
	return `{"all":[{"attr":"context.country","op":"exists"},{"attr":"context.country","op":"nin","value":` + string(b) + `}]}`
}

// within is a condition true where the request comes from a known country in
// countries. A deny on an unknown attribute refuses (it fails closed), so the
// country must be known first or every request without one is refused.
func within(countries ...string) string {
	b, _ := json.Marshal(countries)
	return `{"all":[{"attr":"context.country","op":"exists"},{"attr":"context.country","op":"in","value":` + string(b) + `}]}`
}

// abacSpecs are each Pro or Enterprise organisation's ABAC policies.
var abacSpecs = map[string][]abacSpec{
	"qeet": {
		{name: "Block sanctioned countries", description: "Refuse every action from comprehensively sanctioned jurisdictions (OFAC/UN lists).",
			effect: "deny", resource: "*", action: "*", priority: 1000, enabled: true, by: []who{email("priya@qeet.in")}, created: 300,
			condition: within("CU", "IR", "KP", "SY")},
		{name: "Contractors: business hours only", description: "Contractors may work 09:00–18:00 IST.",
			effect: "deny", resource: "*", action: "*", priority: 500, enabled: true, by: []who{email("priya@qeet.in")}, created: 200,
			condition: contractorHours, edits: []abacEdit{
				{days: 90, change: func(u *abac.UpdateInput) {
					u.Condition = json.RawMessage(contractorHoursWide)
					u.Description = "Contractors may work 08:00–20:00 IST on weekdays (extended for the payments migration)."
				}},
				{days: 10, change: func(u *abac.UpdateInput) { u.Priority = 600 }},
			}},
		{name: "Finance ledgers require MFA", description: "Reading or changing ledgers needs a second factor in this session.",
			effect: "deny", resource: "ledger", action: "read", priority: 400, enabled: true, by: []who{email("priya@qeet.in")}, created: 150,
			condition: withoutMFA, edits: []abacEdit{{days: 30, change: func(u *abac.UpdateInput) { u.Action = "*" }}}},
		{name: "Payouts approved from India only", description: "RBI: settlement approvals only from Indian networks.",
			effect: "deny", resource: "payout", action: "approve", priority: 300, enabled: true, by: []who{both(dept("Security"), guardians)}, created: 140,
			condition: outside("IN")},
		{name: "Engineers read production logs", description: "Engineering may read the production log streams.",
			effect: "allow", resource: "log_stream", action: "read", priority: 100, enabled: true, by: []who{email("priya@qeet.in")}, created: 120,
			condition: `{"attr":"subject.department","op":"eq","value":"Engineering"}`},
		{name: "Everyone reads the employee handbook", description: "The handbook is open to all staff.",
			effect: "allow", resource: "document", action: "read", priority: 10, enabled: true, by: []who{email("aarav@qeet.in")}, created: 110,
			condition: `{}`},
		{name: "Freeze payment config during SOC 2 window", description: "No payment configuration changes while the auditors sample.",
			effect: "deny", resource: "payment_config", action: "write", priority: 900, enabled: true, by: []who{email("priya@qeet.in")}, created: 70,
			condition: `{}`, edits: []abacEdit{{days: 41, change: func(u *abac.UpdateInput) {
				u.Enabled = false
				u.Description = "Lifted after fieldwork closed; kept for the next audit window."
			}}}},
	},
	"northwind": {
		{name: "Loan approvals require MFA", description: "Sanction and disbursal approvals need a second factor.",
			effect: "deny", resource: "loan_application", action: "approve", priority: 800, enabled: true, by: []who{both(dept("Information Security"), guardians)}, created: 280,
			condition: withoutMFA},
		{name: "Credit bureau data from India only", description: "CICRA: bureau reports stay within Indian networks.",
			effect: "deny", resource: "credit_report", action: "*", priority: 700, enabled: true, by: []who{both(dept("Information Security"), guardians)}, created: 260,
			condition: outside("IN"), edits: []abacEdit{{days: 75, change: func(u *abac.UpdateInput) {
				u.Condition = json.RawMessage(outside("IN", "AE"))
				u.Description = "CICRA: bureau reports stay within Indian networks and the Dubai representative office."
			}}}},
		{name: "Contractors: business hours only", description: "Vendor staff may work 09:00–18:00 IST.",
			effect: "deny", resource: "*", action: "*", priority: 600, enabled: true, by: []who{both(dept("Information Security"), guardians)}, created: 200,
			condition: contractorHours},
		{name: "Collections agents see their assigned accounts", description: "A collections officer reads only the loan accounts assigned to them.",
			effect: "allow", resource: "loan_account", action: "read", priority: 200, enabled: true, by: []who{both(dept("Information Security"), guardians)}, created: 150,
			condition: `{"attr":"resource.assigned_to","op":"eq","value":{"attr":"subject.id"}}`},
		{name: "Block bulk export of customer PII", description: "Exports over 1,000 customer rows — pending DPO sign-off.",
			effect: "deny", resource: "customer_record", action: "export", priority: 900, enabled: false, by: []who{both(dept("Information Security"), guardians)}, created: 25,
			condition: `{"attr":"context.row_count","op":"gt","value":1000}`},
	},
	"meridian": {
		{name: "US-only access to PHI", description: "HIPAA: protected health information is reached from US networks only.",
			effect: "deny", resource: "*", action: "*", priority: 1000, enabled: true, by: []who{both(dept("Security"), guardians)}, created: 250,
			condition: outside("US")},
		{name: "Charts outside the assigned unit", description: "Clinicians open charts in their own unit unless they break the glass.",
			effect: "deny", resource: "patient_record", action: "read", priority: 600, enabled: true, by: []who{both(dept("Security"), guardians)}, created: 240,
			condition: `{"all":[{"attr":"context.break_glass","op":"ne","value":true},{"attr":"resource.unit","op":"ne","value":{"attr":"subject.unit"}}]}`},
		{name: "Break-glass chart access", description: "Clinicians may open any chart in an emergency; every use is reviewed.",
			effect: "allow", resource: "patient_record", action: "read", priority: 500, enabled: true, by: []who{both(dept("Security"), guardians)}, created: 240,
			condition: `{"all":[{"attr":"context.break_glass","op":"eq","value":true},{"attr":"subject.title","op":"in","value":["Physician","Registered Nurse","Charge Nurse"]}]}`},
		{name: "E-prescribing requires MFA", description: "DEA EPCS: signing a prescription needs two factors.",
			effect: "deny", resource: "prescription", action: "sign", priority: 800, enabled: true, by: []who{both(dept("Security"), guardians)}, created: 200,
			condition: withoutMFA, edits: []abacEdit{{days: 60, change: func(u *abac.UpdateInput) {
				u.Action = "*"
				u.Description = "DEA EPCS: any prescription action needs two factors."
			}}}},
		{name: "Float pool night-shift access", description: "Trial: float-pool nurses reach every unit at night.",
			effect: "allow", resource: "patient_record", action: "read", priority: 400, enabled: false, by: []who{both(dept("Security"), guardians)}, created: 90,
			condition: `{"all":[{"attr":"subject.team","op":"eq","value":"Float Pool"},{"any":[{"attr":"context.hour","op":"gte","value":19},{"attr":"context.hour","op":"lt","value":7}]}]}`,
			edits:     []abacEdit{{days: 61, change: func(u *abac.UpdateInput) { u.Enabled = false }}}},
	},
	"lumen": {
		{name: "Staff-only workspace deletion", description: "Only Lumen staff may delete a customer workspace.",
			effect: "deny", resource: "workspace", action: "delete", priority: 700, enabled: true, by: []who{email("jonas.becker@lumenlabshq.dev")}, created: 200,
			condition: `{"not":{"attr":"subject.email","op":"suffix","value":"@lumenlabshq.dev"}}`},
		{name: "Free workspaces: three projects", description: "The free tier holds at most three projects.",
			effect: "deny", resource: "project", action: "create", priority: 300, enabled: true, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 150,
			condition: `{"all":[{"attr":"resource.plan","op":"eq","value":"free"},{"attr":"resource.project_count","op":"gte","value":3}]}`,
			edits: []abacEdit{{days: 20, change: func(u *abac.UpdateInput) {
				u.Condition = json.RawMessage(`{"all":[{"attr":"resource.plan","op":"eq","value":"free"},{"attr":"resource.project_count","op":"gte","value":5}]}`)
				u.Name, u.Description = "Free workspaces: five projects", "The free tier holds at most five projects (raised for the October launch)."
			}}}},
		{name: "EU data stays in the EU", description: "GDPR: exports only to EU regions.",
			effect: "deny", resource: "*", action: "export", priority: 900, enabled: true, by: []who{email("jonas.becker@lumenlabshq.dev")}, created: 120,
			condition: `{"all":[{"attr":"context.region","op":"exists"},{"attr":"context.region","op":"nin","value":["eu-west-1","eu-central-1"]}]}`},
	},
}

// consoleResources are the resource types of Qeet ID's own permissions, which
// the console's route guard checks policies against.
var consoleResources = []string{"tenant", "user", "role", "audit", "group", "connection", "apikey", "secret",
	"webhook", "billing", "branding", "policy", "gdpr", "analytics"}

// abac writes the organisation's ABAC policies through the ABAC service, then
// edits some so their history has versions.
func (d *dev) abac(o *world.Org) {
	w := d.w
	if !o.Has("pro") {
		return
	}
	for _, s := range abacSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		in := abac.CreateInput{Name: s.name, Description: s.description, Effect: s.effect, ResourceType: s.resource,
			Action: s.action, Condition: json.RawMessage(s.condition), Priority: s.priority, Enabled: true}
		d.consoleSafe(o, in.Effect, in.ResourceType, in.Condition, in.Enabled)
		var p *abac.Policy
		w.At(at, func() {
			var err error
			p, err = w.Deps.ABAC.Service.Create(w.Ctx, o.ID, in, d.as(by))
			w.Check(err, "ABAC policy "+s.name)
		})
		u := abac.UpdateInput{Name: p.Name, Description: p.Description, Effect: p.Effect, ResourceType: p.ResourceType,
			Action: p.Action, Condition: p.Condition, Priority: p.Priority, Enabled: p.Enabled}
		edits := s.edits
		if !s.enabled && len(edits) == 0 {
			edits = []abacEdit{{days: s.created / 2, change: func(u *abac.UpdateInput) { u.Enabled = false }}}
		}
		for _, e := range edits {
			e.change(&u)
			et := d.when(o, e.days, by)
			editor := person(o, et, email(by.Email), guardians)
			d.consoleSafe(o, u.Effect, u.ResourceType, u.Condition, u.Enabled)
			w.At(et, func() {
				_, err := w.Deps.ABAC.Service.Update(w.Ctx, p.ID, o.ID, u, d.as(editor))
				w.Check(err, "edit ABAC policy "+s.name)
			})
		}
	}
}

// consoleSafe stops the seed if an enabled deny policy would refuse the
// console's own requests, which carry no subject or context attributes: a
// tester would be locked out of the organisation.
func (d *dev) consoleSafe(o *world.Org, effect, resource string, cond json.RawMessage, enabled bool) {
	if effect != "deny" || !enabled {
		return
	}
	for _, rt := range consoleResources {
		if resource != "*" && resource != rt {
			continue
		}
		applies, err := abac.EvaluateCondition(cond, effect, abac.AttributeBag{
			"subject":  abac.SubjectAttributes(o.Owner.ID.String(), o.ID),
			"resource": {"type": rt, "id": ""},
			"context":  {},
		})
		if applies || err != nil {
			d.w.Check(errString("deny policy "+string(cond)+" would refuse the console's "+rt+" requests"), "ABAC policy in "+o.Spec.Slug)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// slug is a group or team name as a relationship object id.
func slug(name string) string {
	r := strings.NewReplacer(" & ", "-and-", ", ", "-", " ", "-", "&", "and", ",", "")
	return strings.ToLower(r.Replace(name))
}

// relSession is one sitting at the relationship editor: who and when, and
// the tuples written.
type relSession struct {
	o      *world.Org
	by     *world.Person
	at     time.Time
	tuples [][3]string // object, relation, subject
}

func (s *relSession) add(object, relation, subject string) {
	s.tuples = append(s.tuples, [3]string{object, relation, subject})
}

// user is p as a relationship subject.
func user(p *world.Person) string { return "user:" + p.ID.String() }

// members adds group:<team> member tuples for everyone in team there at the
// session (and still there, or there until later), and returns the
// group's userset.
func (s *relSession) members(team string) string {
	g := "group:" + slug(team)
	for _, p := range s.o.People {
		if p.ID == uuid.Nil || p.Joined.After(s.at) || (p.Status == world.StatusDeleted && p.Since.Before(s.at)) {
			continue
		}
		if p.Team == team || (p.Team == "" && p.Department == team) {
			s.add(g, "member", user(p))
		}
	}
	return g + "#member"
}

// write writes the session's tuples through the ReBAC service, one request
// each, and returns their ids by object, relation and subject.
func (d *dev) write(s *relSession) map[[3]string]uuid.UUID {
	w := d.w
	ids := map[[3]string]uuid.UUID{}
	w.At(s.at, func() {
		for _, t := range s.tuples {
			tp, err := w.Deps.ReBAC.Service.Write(w.Ctx, s.o.ID, t[0], t[1], t[2], d.as(s.by))
			w.Check(err, "relationship "+t[0]+"#"+t[1])
			ids[t] = tp.ID
		}
	})
	return ids
}

// rebac writes each organisation's relationship graph: team groups (nested
// into departments), the folders, projects and documents they reach, and
// document:readme — the object the console's relationship screen opens on.
func (d *dev) rebac(o *world.Org) {
	switch o.Spec.Slug {
	case "qeet":
		at := d.when(o, 200)
		s := &relSession{o: o, by: person(o, at, email("rohan@qeet.in")), at: at}
		eng := "group:engineering"
		for _, t := range []string{"Qeet ID", "Qeet Pay", "Qeet People", "Qeet Notify", "Qeet Logs", "Qeet AI", "Qeet Circle", "Qeetrix", "Site Reliability"} {
			s.add(eng, "member", s.members(t))
		}
		s.members("Security Engineering")
		s.members("Product Management")
		s.members("Finance")
		ids := d.write(s)
		d.leaversLeave(o, ids)
		d.joinersJoin(o, at, s.by, []string{"Qeet ID", "Qeet Pay", "Qeet People", "Qeet Notify", "Qeet Logs", "Qeet AI", "Qeet Circle", "Qeetrix", "Site Reliability", "Security Engineering", "Product Management", "Finance"})

		at = d.when(o, 190)
		s = &relSession{o: o, by: person(o, at, email("aarav@qeet.in")), at: at}
		s.add("folder:engineering-handbook", "owner", user(s.by))
		s.add("folder:engineering-handbook", "viewer", eng+"#member")
		s.add("document:readme", "parent", "folder:engineering-handbook")
		s.add("document:readme", "owner", user(person(o, at, email("rohan@qeet.in"))))
		s.add("document:readme", "editor", "group:identity-platform#member")
		s.add("document:readme", "viewer", "folder:engineering-handbook#viewer")
		s.add("document:readme", "viewer", "group:product-management#member")
		s.add("document:oncall-runbook", "parent", "folder:engineering-handbook")
		s.add("document:oncall-runbook", "editor", "group:site-reliability#member")
		s.add("document:oncall-runbook", "viewer", eng+"#member")
		s.add("document:oncall-runbook", "viewer", "group:security-engineering#member")
		d.write(s)

		at = d.when(o, 120)
		s = &relSession{o: o, by: person(o, at, email("priya@qeet.in")), at: at}
		s.add("folder:finance", "owner", user(person(o, at, email("vikram@qeet.in"))))
		s.add("folder:finance", "viewer", "group:finance#member")
		s.add("document:fy27-budget", "parent", "folder:finance")
		s.add("document:fy27-budget", "viewer", "folder:finance#viewer")
		s.add("document:fy27-budget", "editor", user(person(o, at, email("vikram@qeet.in"))))
		d.write(s)

		at = d.when(o, 60)
		s = &relSession{o: o, by: person(o, at, email("aarav@qeet.in")), at: at}
		s.add("project:qeet-id-1-0", "owner", user(s.by))
		s.add("project:qeet-id-1-0", "member", "group:identity-platform#member")
		s.add("project:qeet-id-1-0", "member", "group:frontend#member")
		s.add("project:qeet-id-1-0", "viewer", "group:product-management#member")
		s.add("document:qeet-id-1-0-launch-plan", "parent", "project:qeet-id-1-0")
		s.add("document:qeet-id-1-0-launch-plan", "owner", user(person(o, at, email("tara@qeet.in"))))
		s.add("document:qeet-id-1-0-launch-plan", "editor", "project:qeet-id-1-0#member")
		s.add("document:readme", "viewer", user(person(o, at, email("grace@qeet.in"))))
		d.write(s)
	case "lumen":
		at := d.when(o, 150)
		s := &relSession{o: o, by: person(o, at, email("lucia.garcia@lumenlabshq.dev")), at: at}
		teams := []string{"Core Platform", "CLI & SDKs", "Infrastructure"}
		for _, t := range teams {
			s.add("group:engineering", "member", s.members(t))
		}
		s.members("Docs & Community")
		s.add("workspace:lumen-cloud", "admin", user(o.Owner))
		s.add("workspace:lumen-cloud", "member", "group:engineering#member")
		s.add("workspace:lumen-cloud", "member", "group:docs-and-community#member")
		s.add("repository:lumen-cli", "maintainer", "group:cli-and-sdks#member")
		s.add("repository:lumen-cli", "reader", "workspace:lumen-cloud#member")
		s.add("document:readme", "parent", "repository:lumen-cli")
		s.add("document:readme", "owner", user(s.by))
		s.add("document:readme", "editor", "group:docs-and-community#member")
		s.add("document:readme", "viewer", "repository:lumen-cli#reader")
		s.add("document:api-reference", "parent", "repository:lumen-cli")
		s.add("document:api-reference", "editor", "group:docs-and-community#member")
		s.add("document:api-reference", "viewer", "workspace:lumen-cloud#member")
		ids := d.write(s)
		d.leaversLeave(o, ids)
		d.joinersJoin(o, at, s.by, append(teams, "Docs & Community"))
	case "northwind":
		at := d.when(o, 180)
		s := &relSession{o: o, by: person(o, at, both(dept("Information Security"), guardians)), at: at}
		cro := person(o, at, title("Chief Risk Officer"))
		uw := s.members("Credit Underwriting")
		s.add("folder:credit-policies", "owner", user(cro))
		s.add("folder:credit-policies", "viewer", uw)
		s.add("folder:credit-policies", "viewer", s.members("Regulatory Compliance"))
		s.add("document:readme", "parent", "folder:credit-policies")
		s.add("document:readme", "owner", user(cro))
		s.add("document:readme", "viewer", "folder:credit-policies#viewer")
		s.add("document:sanction-matrix-fy27", "parent", "folder:credit-policies")
		s.add("document:sanction-matrix-fy27", "editor", user(cro))
		s.add("document:sanction-matrix-fy27", "viewer", uw)
		ids := d.write(s)
		d.leaversLeave(o, ids)
	case "meridian":
		at := d.when(o, 160)
		s := &relSession{o: o, by: person(o, at, email("marcus.brooks@meridianhealth.us")), at: at}
		desk := s.members("Service Desk")
		s.add("group:information-technology", "member", desk)
		s.add("group:information-technology", "member", s.members("Infrastructure"))
		s.add("document:readme", "owner", user(s.by))
		s.add("document:readme", "editor", desk)
		s.add("document:readme", "viewer", "group:information-technology#member")
		s.add("document:downtime-procedures", "editor", user(o.Owner))
		s.add("document:downtime-procedures", "viewer", "group:information-technology#member")
		ids := d.write(s)
		d.leaversLeave(o, ids)
	}
}

// leaversLeave deletes the group memberships of people who left, the day
// they went.
func (d *dev) leaversLeave(o *world.Org, ids map[[3]string]uuid.UUID) {
	w := d.w
	for _, p := range o.People {
		if p.Status != world.StatusDeleted || p.ID == uuid.Nil {
			continue
		}
		for t, id := range ids {
			if t[1] != "member" || t[2] != user(p) {
				continue
			}
			by := person(o, p.Since, guardians)
			w.At(p.Since.Add(3*time.Hour), func() {
				w.Check(w.Deps.ReBAC.Service.Delete(w.Ctx, id, o.ID, d.as(by)), "delete relationship of "+p.Email)
			})
		}
	}
}

// joinersJoin adds each person who joined a team since the graph was drawn
// to its group the working day after they started.
func (d *dev) joinersJoin(o *world.Org, since time.Time, by *world.Person, teams []string) {
	w := d.w
	for _, p := range o.People {
		at := w.WorkHours(p.Joined.Add(24*time.Hour), o.Loc)
		if p.ID == uuid.Nil || !p.Joined.After(since) || at.After(w.Now.Add(-time.Hour)) ||
			(p.Status == world.StatusDeleted && p.Since.Before(at)) {
			continue
		}
		s := &relSession{o: o, by: by, at: at}
		for _, t := range teams {
			if p.Team == t || (p.Team == "" && p.Department == t) {
				s.add("group:"+slug(t), "member", user(p))
			}
		}
		if len(s.tuples) > 0 {
			d.leaversLeave(o, d.write(s))
		}
	}
}

// limit is one rate-limit override: requests a second and burst.
type limit struct {
	key      string
	rate     float64
	capacity int
}

// limitChange is one save of the rate-limit form.
type limitChange struct {
	days   float64
	by     []who
	limits []limit
}

// limitChanges are the organisations that tightened their API limits.
var limitChanges = map[string][]limitChange{
	"northwind": {{150, []who{both(dept("Information Security"), guardians)}, []limit{{"tenant", 60, 300}, {"api_key", 20, 100}}}},
	"lumen": {
		{80, []who{email("jonas.becker@lumenlabshq.dev")}, []limit{{"api_key", 25, 120}}},
		{9, []who{email("jonas.becker@lumenlabshq.dev")}, []limit{{"api_key", 35, 150}, {"user", 20, 80}}},
	},
}

// rateLimits saves the organisation's rate-limit overrides as the console's
// rate-limit form does.
func (d *dev) rateLimits(o *world.Org) {
	w := d.w
	for _, c := range limitChanges[o.Spec.Slug] {
		at := d.when(o, c.days)
		by := person(o, at, c.by...)
		meta := map[string]any{}
		w.At(at, func() {
			w.Tx("rate limits of "+o.Spec.Slug, func(tx pgx.Tx) error {
				for _, l := range c.limits {
					if _, err := tx.Exec(w.Ctx, `
						INSERT INTO platform.rate_limit_overrides (tenant_id, limit_key, rate, capacity, updated_at)
						VALUES ($1, $2, $3, $4, NOW())
						ON CONFLICT (tenant_id, limit_key) DO UPDATE SET
						    rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW()`,
						o.ID, l.key, l.rate, l.capacity); err != nil {
						return err
					}
					meta[l.key] = map[string]any{"rate": l.rate, "capacity": l.capacity}
				}
				return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, "rate_limits.updated", "tenant", o.ID, meta))
			})
		})
	}
}
