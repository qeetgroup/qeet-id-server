// Package census creates the seeded organizations: their owners, plans, roles,
// groups and people. It also decides each person's part — who left or was
// suspended, who uses which second factor, which accounts are for testers —
// which the later steps carry out.
package census

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/group"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
)

// Seed plans and creates every organization.
func Seed(w *world.World) {
	for _, s := range specs() {
		w.Orgs = append(w.Orgs, plan(w, s))
	}
	addGuests(w)
	for _, o := range w.Orgs {
		create(w, o)
	}
	for _, o := range w.Orgs {
		for _, g := range o.Guests {
			for _, r := range g.GuestOf {
				if r.Org == o {
					grantGuest(w, g, r)
				}
			}
		}
		billing := ""
		if o.Spec.Billing != "active" {
			billing = "·" + o.Spec.Billing
		}
		w.Note("Organizations", "%-26s %-19s %3d people   %s", o.Spec.Name, o.Spec.Plan+billing, len(o.People), o.Spec.Domain)
		w.Note("Organizations", "  %s", o.Spec.Story)
	}
}

// fixed is a person whose name and address testers rely on.
type fixed struct {
	email, first, last, title, dept, team, role, login string
}

// named are each organization's fixed people; the first is its owner. The
// rest of every roster is generated.
var named = map[string][]fixed{
	"qeet": {
		{"saibabu@qeet.in", "Mareedu", "Saibabu", "Founder & CEO", "", "", world.RoleOwner, "Owner of Qeet Group and Qeet Sandbox (organization picker)"},
		{"aarav@qeet.in", "Aarav", "Mehta", "VP Engineering", "Engineering", "", world.RoleAdmin, "Admin — signs in with a TOTP code (secret below)"},
		{"priya@qeet.in", "Priya", "Nair", "Head of Security", "Security", "", world.RoleAdmin, "Admin; also an owner of Qeet Sandbox"},
		{"tara@qeet.in", "Tara", "Menon", "Head of Product", "Product", "", world.RoleMember, ""},
		{"vikram@qeet.in", "Vikram", "Reddy", "Head of Operations", "Operations", "", world.RoleBilling, "Billing Admin — billing pages only"},
		{"rohan@qeet.in", "Rohan", "Gupta", "Staff Engineer", "Engineering", "Qeet ID", world.RoleDeveloper, "Developer — restricted console"},
		{"diego@qeet.in", "Diego", "Fernández", "Senior Software Engineer", "Engineering", "Qeet Pay", world.RoleDeveloper, ""},
		{"ananya@qeet.in", "Ananya", "Iyer", "Senior Software Engineer", "Engineering", "Qeetrix", world.RoleDeveloper, ""},
		{"sneha@qeet.in", "Sneha", "Kulkarni", "Support Lead", "Customer Success", "Support", world.RoleMember, "Member — read-only console"},
		{"grace@qeet.in", "Grace", "Okafor", "Solutions Engineer", "Customer Success", "Onboarding", world.RoleHelpdesk, "Helpdesk; also helps Northwind Capital as a guest"},
	},
	"qeet-sandbox": {
		{"qa@qeet.in", "QA", "Automation", "Test account", "", "", world.RoleOwner, ""},
	},
	"northwind": {
		{"rajesh.iyer@northwindcapital.in", "Rajesh", "Iyer", "Chief Technology Officer", "Technology", "", world.RoleOwner, "Owner — MFA required for everyone (TOTP secret below)"},
		{"kavya.menon@northwindcapital.in", "Kavya", "Menon", "IT Operations Manager", "Technology", "IT Operations", world.RoleITAdmin, "IT Admin"},
		{"farhan.qureshi@northwindcapital.in", "Farhan", "Qureshi", "Senior Internal Auditor", "Compliance", "Internal Audit", world.RoleAuditor, "Auditor — reads everything, changes nothing"},
	},
	"meridian": {
		{"jennifer.walsh@meridianhealth.us", "Jennifer", "Walsh", "Chief Information Officer", "Information Technology", "", world.RoleOwner, "Owner"},
		{"marcus.brooks@meridianhealth.us", "Marcus", "Brooks", "Service Desk Lead", "Information Technology", "Service Desk", world.RoleHelpdesk, "Helpdesk"},
		{"linda.park@meridianhealth.us", "Linda", "Park", "Chief Privacy Officer", "Privacy & Compliance", "", world.RoleAuditor, ""},
	},
	"lumen": {
		{"jonas.becker@lumenlabshq.dev", "Jonas", "Becker", "CTO", "Engineering", "", world.RoleOwner, "Owner — hosted sign-up, social sign-in and magic links"},
		{"lucia.garcia@lumenlabshq.dev", "Lucía", "García", "Senior Software Engineer", "Engineering", "CLI & SDKs", world.RoleDeveloper, "Developer; also a guest Developer at Aster Retail"},
	},
	"aster": {
		{"meera.shetty@asterretail.in", "Meera", "Shetty", "Founder & CEO", "", "", world.RoleOwner, "Owner — Starter plan"},
	},
	"vertex": {
		{"tyler.morgan@vertexfreightco.us", "Tyler", "Morgan", "IT Manager", "IT", "", world.RoleOwner, "Owner — Pro trial, set-up half done"},
	},
	"kestrel": {
		{"sanjay.deshpande@kestrelinsurance.in", "Sanjay", "Deshpande", "Principal Officer", "Broking", "", world.RoleOwner, "Owner — refused from localhost: sign-in only from the office network"},
	},
	"cobalt": {
		{"oliver.bennett@cobaltcreative.co.uk", "Oliver", "Bennett", "Founding Partner", "", "", world.RoleOwner, "Owner — Starter cancelled, ends with the month"},
		{"poppy.clarke@cobaltcreative.co.uk", "Poppy", "Clarke", "Partner", "", "", world.RoleOwner, ""},
		{"rory.campbell@cobaltcreative.co.uk", "Rory", "Campbell", "Partner", "", "", world.RoleOwner, ""},
	},
	"fjord": {
		{"ingrid.solberg@fjordanalytics.no", "Ingrid", "Solberg", "Founder", "", "", world.RoleOwner, "Owner — new organization, onboarding checklist open"},
	},
}

// taken is every address planned so far, across organizations.
var taken = map[string]bool{}

// plan decides the organization's people without touching the database.
func plan(w *world.World, s world.OrgSpec) *world.Org {
	o := &world.Org{Spec: s, Roles: map[string]uuid.UUID{}, Groups: map[string]uuid.UUID{}}
	newPerson := func(l world.Locale, first, last, email string) *world.Person {
		city := l.Cities[0]
		for _, c := range l.Cities {
			if c.Name == s.City {
				city = c
			}
		}
		if w.Chance(0.2) {
			city = world.Pick(w, l.Cities)
		}
		p := &world.Person{Org: o, First: first, Last: last, Email: email, City: city.Name, Country: l.Country, Status: world.StatusActive,
			Device: w.NewDevice(l, city, false), Mobile: w.NewDevice(l, city, true)}
		if w.Chance(0.75) {
			p.Phone = l.Phone(w)
		}
		taken[email] = true
		return p
	}
	generated := func() *world.Person {
		for {
			l := world.Pick(w, s.Locales)
			first, last := world.Pick(w, l.First), world.Pick(w, l.Last)
			if email := world.EmailLocal(first, last) + "@" + s.Domain; !taken[email] {
				return newPerson(l, first, last, email)
			}
		}
	}

	// The fixed people first, the owner at their head.
	for _, f := range named[s.Slug] {
		l := s.Locales[0]
		if f.first == "Diego" || f.first == "Lucía" {
			l = world.Europe
		}
		p := newPerson(l, f.first, f.last, f.email)
		p.Title, p.Department, p.Team, p.Role, p.Login = f.title, f.dept, f.team, f.role, f.login
		o.People = append(o.People, p)
	}
	o.Owner = o.People[0]

	// Department heads, then everyone else by department share.
	heads := map[string]*world.Person{}
	for _, p := range o.People {
		if p.Department != "" && p.Team == "" {
			heads[p.Department] = p
		}
	}
	total := 0
	for _, d := range s.Depts {
		total += d.Share
		if heads[d.Name] == nil && len(o.People) < s.Size {
			p := generated()
			p.Title, p.Department, p.Role = d.Head, d.Name, headRole(d)
			heads[d.Name] = p
			o.People = append(o.People, p)
		}
	}
	for i := 0; len(o.People) < s.Size && total > 0; i++ {
		d := pickDept(w, s.Depts, total)
		p := generated()
		p.Department, p.Role, p.Title, p.Team = d.Name, d.Role, world.Pick(w, d.Titles), d.Teams[i%len(d.Teams)]
		o.People = append(o.People, p)
	}
	// Managers: a team's first member leads it and reports to the department
	// head; the rest report to the lead.
	leads := map[string]*world.Person{}
	for i, p := range o.People {
		p.EmployeeID = fmt.Sprintf("%s-%04d", strings.ToUpper(s.Slug[:3]), 1001+i)
		switch key := p.Department + "/" + p.Team; {
		case p == o.Owner:
		case p.Department == "" || heads[p.Department] == p:
			p.Manager = o.Owner
		case leads[key] == nil:
			leads[key], p.Manager = p, heads[p.Department]
		default:
			p.Manager = leads[key]
		}
	}
	provisioning(w, o)
	lifecycle(o)
	factors(w, o)
	return o
}

// headRole is the role a department head holds: technical heads administer
// the organization, a finance head runs its billing.
func headRole(d world.Dept) string {
	switch d.Role {
	case world.RoleDeveloper, world.RoleITAdmin, world.RoleSecurity:
		return world.RoleAdmin
	}
	if d.Name == "Finance" || d.Name == "Operations" {
		return world.RoleBilling
	}
	return d.Role
}

func pickDept(w *world.World, depts []world.Dept, total int) world.Dept {
	n := w.Rand.IntN(total)
	for _, d := range depts {
		if n < d.Share {
			return d
		}
		n -= d.Share
	}
	return depts[0]
}

// provisioning marks who arrives from the identity provider: everyone but the
// owner where SCIM pushes accounts.
func provisioning(w *world.World, o *world.Org) {
	if !o.Spec.Features.SCIM {
		return
	}
	for _, p := range o.People[1:] {
		p.Provisioned = true
		p.ExternalID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.Email)).String()
		if o.Spec.Features.SSO == "okta" {
			p.ExternalID = "00u" + w.Token(world.Alnum, 17)
		}
	}
}

// lifecycle decides who left and who is suspended (about one in twenty-five
// each, never a test account or a department head), and who never verified
// their address (one person each larger organization added by hand).
func lifecycle(o *world.Org) {
	if len(o.People) < 12 {
		return
	}
	var ordinary []*world.Person
	for _, p := range o.People[1:] {
		if p.Login == "" && p.Manager != o.Owner {
			ordinary = append(ordinary, p)
		}
	}
	n := max(1, len(o.People)/25)
	leavers, suspended := n, n
	reasons := []string{"offboarding", "suspicious_activity", "inactive", "policy_violation"}
	for i, p := range ordinary {
		switch {
		case i%7 != 3: // spread over the roster
		case leavers > 0:
			p.Status, leavers = world.StatusDeleted, leavers-1
		case suspended > 0:
			p.Status, p.Reason = world.StatusSuspended, reasons[(n-suspended)%len(reasons)]
			suspended--
		}
	}
	for i := len(ordinary) - 1; i >= 0; i-- {
		if p := ordinary[i]; !p.Provisioned && p.Status == world.StatusActive {
			p.Unverified = true
			break
		}
	}
}

// factors decides each person's second factors from the organization's MFA
// policy: everyone where it is required, administrators where only they must,
// and the security-minded few where it's optional.
func factors(w *world.World, o *world.Org) {
	for _, p := range o.People {
		admin := p.Role == world.RoleOwner || p.Role == world.RoleAdmin || p.Role == world.RoleITAdmin || p.Role == world.RoleSecurity
		adopt := 0.3
		switch {
		case o.Spec.Features.MFA == "required":
			adopt = 1
		case o.Spec.Features.MFA == "admin_only" && admin:
			adopt = 1
		case o.Spec.Features.MFA == "admin_only":
			adopt = 0.25
		case strings.HasPrefix(o.Spec.Industry, "Software"):
			adopt = 0.7
		}
		if p.Unverified || p.Status == world.StatusDeleted || !w.Chance(adopt) {
			continue
		}
		p.MFA = []string{"totp", "recovery"}
		if w.Chance(0.2) {
			p.MFA = append(p.MFA, "push")
		}
	}
	// Fixed choices testers rely on: the founder and most Qeet test accounts
	// sign in with a password alone.
	if o.Spec.Slug == "qeet" {
		for _, e := range []string{"saibabu@qeet.in", "rohan@qeet.in", "sneha@qeet.in", "vikram@qeet.in", "grace@qeet.in", "priya@qeet.in"} {
			o.Person(e).MFA = nil
		}
		o.Person("aarav@qeet.in").MFA = []string{"totp", "recovery"}
	}
}

// addGuests gives a few people roles in organizations other than their own.
func addGuests(w *world.World) {
	guest := func(email, slug, role string) {
		p, o := w.Person(email), w.Org(slug)
		p.GuestOf = append(p.GuestOf, world.GuestRole{Org: o, Role: role})
		o.Guests = append(o.Guests, p)
	}
	w.Org("qeet-sandbox").Owner = w.Org("qeet").Owner
	guest("priya@qeet.in", "qeet-sandbox", world.RoleOwner)
	guest("grace@qeet.in", "northwind", world.RoleHelpdesk)
	guest("lucia.garcia@lumenlabshq.dev", "aster", world.RoleDeveloper)
}

// permissions are each role's grants. Admin and the owner hold everything.
var permissions = map[string][]string{
	world.RoleITAdmin: {"organization.read", "user.read", "user.write", "user.delete", "user.suspend", "user.credentials", "session.revoke",
		"member.invite", "group.read", "group.write", "role.read", "role.write",
		"connection.read", "connection.write", "policy.read", "policy.write", "branding.write", "audit.read", "analytics.read"},
	world.RoleHelpdesk: {"organization.read", "user.read", "user.write", "user.suspend", "user.credentials", "session.revoke",
		"group.read", "role.read", "audit.read"},
	world.RoleSecurity: {"organization.read", "user.read", "group.read", "role.read", "audit.read", "audit.write", "analytics.read",
		"policy.read", "policy.write", "connection.read", "secret.read", "webhook.read", "apikey.read"},
	world.RoleAuditor: {"organization.read", "user.read", "group.read", "role.read", "audit.read", "analytics.read", "policy.read",
		"connection.read", "apikey.read", "webhook.read", "billing.read"},
	world.RoleDeveloper: {"organization.read", "user.read", "group.read", "role.read", "apikey.read", "apikey.write",
		"webhook.read", "webhook.write", "secret.read", "secret.write", "connection.read", "analytics.read"},
	world.RoleBilling: {"organization.read", "billing.read", "billing.write", "user.read"},
	world.RoleMember:  {"organization.read", "user.read", "role.read", "group.read"},
}

var roleDescriptions = map[string]string{
	world.RoleAdmin:     "Full administrative access to the organization",
	world.RoleITAdmin:   "Manages people, groups, connections and sign-in policy",
	world.RoleHelpdesk:  "Helps people sign in: resets, unlocks and profile changes",
	world.RoleSecurity:  "Investigates sign-in activity and manages security policy",
	world.RoleAuditor:   "Reads everything for audits; changes nothing",
	world.RoleDeveloper: "Builds integrations: API keys, webhooks, secrets and applications",
	world.RoleBilling:   "Manages the subscription, invoices and payment details",
	world.RoleMember:    "Standard access: sees the directory, changes nothing",
}

// builtinRoles are the seed's roles every organization has built in, by the
// built-in role's name.
var builtinRoles = map[string]string{world.RoleAdmin: "admin", world.RoleMember: "member", world.RoleOwner: "owner"}

// create writes the organization: its owner signs up and creates it, takes
// its plan, sets up roles and groups, then adds its people.
func create(w *world.World, o *world.Org) {
	d, ctx, s, owner := w.Deps, w.Ctx, o.Spec, o.Owner
	if owner.Org == o {
		_, u, _, err := d.Auth.Service.Signup(ctx, auth.SignupInput{Email: owner.Email, Password: w.Password, DisplayName: owner.Name(),
			IP: owner.Device.IP, UserAgent: owner.Device.UserAgent})
		w.Check(err, "sign up "+owner.Email)
		owner.ID = u.ID
		w.Check(d.User.Repo.MarkEmailVerified(ctx, u.ID), "verify "+owner.Email)
	}
	var created struct {
		ID uuid.UUID `json:"organization_id"`
	}
	w.API.Do(nil, owner, "POST", "/organizations", organization.CreateInput{Slug: s.Slug, Name: s.Name, LogoURL: monogram(s.Name, s.Brand),
		Metadata: map[string]any{"industry": s.Industry, "headquarters": s.City + ", " + s.Country, "website": "https://" + s.Domain}}, &created)
	o.ID = created.ID
	if owner.Org == o {
		in := user.UpdateInput{Metadata: profile(owner)}
		if owner.Phone != "" {
			in.Phone = &owner.Phone
		}
		_, err := d.User.Repo.Update(ctx, owner.ID, in)
		w.Check(err, "profile of "+owner.Email)
	}
	subscribe(w, o)

	// Roles: the ones its people hold, plus Admin, Auditor and Member.
	roles, err := d.RBAC.Repo.ListRoles(ctx, o.ID)
	w.Check(err, "roles of "+s.Slug)
	for _, r := range roles {
		for seed, builtin := range builtinRoles {
			if r.IsSystem && r.Name == builtin {
				o.Roles[seed] = r.ID
			}
		}
	}
	if o.Has("starter") {
		want := map[string]bool{world.RoleAdmin: true, world.RoleMember: true, world.RoleAuditor: len(o.People) >= 20}
		for _, p := range append(o.People, o.Guests...) {
			want[p.Role] = true
		}
		for _, g := range o.Guests {
			for _, r := range g.GuestOf {
				want[r.Role] = want[r.Role] || r.Org == o
			}
		}
		for _, name := range []string{world.RoleITAdmin, world.RoleSecurity, world.RoleHelpdesk, world.RoleDeveloper, world.RoleAuditor, world.RoleBilling} {
			if want[name] {
				r, err := d.RBAC.Service.CreateRole(ctx, o.ID, name, roleDescriptions[name], owner.Actor())
				w.Check(err, "role "+name+" in "+s.Slug)
				o.Roles[name] = r.ID
				grant(w, o, r.ID, name, owner)
			}
		}
	}

	// Groups: a group per department, a nested group per team.
	for _, dpt := range s.Depts {
		g, err := d.Group.Service.Create(ctx, group.CreateInput{OrganizationID: o.ID, Name: dpt.Name, Description: "Everyone in " + dpt.Name}, owner.Actor())
		w.Check(err, "group "+dpt.Name)
		o.Groups[dpt.Name] = g.ID
		for _, team := range dpt.Teams {
			tg, err := d.Group.Service.Create(ctx, group.CreateInput{OrganizationID: o.ID, ParentID: &g.ID, Name: team,
				Description: dpt.Name + " — " + team}, owner.Actor())
			w.Check(err, "group "+team)
			o.Groups[team] = tg.ID
		}
	}

	// People, added by an administrator in the console with the shared
	// password set, their role given and their team joined.
	for _, p := range o.People {
		if p != owner {
			by := adder(o)
			var u user.User
			w.API.Do(o, by, "POST", "/users", user.CreateInput{Email: p.Email, DisplayName: p.Name(), Phone: p.Phone, Metadata: profile(p)}, &u)
			p.ID = u.ID
			w.Check(d.User.Repo.SetPassword(ctx, p.ID, w.PasswordHash), "password of "+p.Email)
			if !p.Unverified {
				w.Check(d.User.Repo.MarkEmailVerified(ctx, p.ID), "verify "+p.Email)
			}
			w.Check(d.RBAC.Service.AssignRole(ctx, p.ID, o.ID, o.Roles[p.Role], &by.ID, by.Actor()), "assign "+p.Email)
		}
		team := p.Team
		if team == "" {
			team = p.Department
		}
		if g, ok := o.Groups[team]; ok {
			w.Check(d.Group.Service.AddMember(ctx, g, p.ID, o.ID, owner.Actor()), "group member "+p.Email)
		}
	}
}

// adder is who adds people to o: its first IT administrator or Admin
// already there, else the owner.
func adder(o *world.Org) *world.Person {
	for _, p := range o.People {
		if p.ID != uuid.Nil && (p.Role == world.RoleITAdmin || p.Role == world.RoleAdmin) {
			return p
		}
	}
	return o.Owner
}

// profiles are the paying organizations' billing details, so their invoices
// carry them (and GST where the organization is registered for it).
var profiles = map[string]billing.BillingProfile{
	"qeet": {LegalName: "Qeet Group Private Limited", BillingEmail: "accounts@qeet.in", AddressLine1: "4th Floor, Prestige Atlanta, 80 Feet Road",
		AddressLine2: "Koramangala 1A Block", City: "Bengaluru", State: "Karnataka", PostalCode: "560034", TaxIDType: "gstin", TaxID: "29AAKCQ4187M1ZJ"},
	"northwind": {LegalName: "Northwind Capital Finance Limited", BillingEmail: "accounts.payable@northwindcapital.in", AddressLine1: "Level 12, One BKC, G Block",
		AddressLine2: "Bandra Kurla Complex, Bandra (East)", City: "Mumbai", State: "Maharashtra", PostalCode: "400051", TaxIDType: "gstin", TaxID: "27AAFCN8312K1Z8"},
	"meridian": {LegalName: "Meridian Health System, Inc.", BillingEmail: "ap@meridianhealth.us", AddressLine1: "800 Boylston Street, Suite 1400",
		City: "Boston", State: "Massachusetts", PostalCode: "02199"},
	"lumen": {LegalName: "Lumen Labs GmbH", BillingEmail: "billing@lumenlabshq.dev", AddressLine1: "Torstraße 140", City: "Berlin", State: "Berlin",
		PostalCode: "10119", TaxIDType: "vat", TaxID: "DE318472951"},
	"aster": {LegalName: "Aster Retail Private Limited", BillingEmail: "finance@asterretail.in", AddressLine1: "No. 42, 2nd Floor, 100 Feet Road",
		AddressLine2: "HAL 2nd Stage, Indiranagar", City: "Bengaluru", State: "Karnataka", PostalCode: "560038", TaxIDType: "gstin", TaxID: "29AAJCA5521Q1Z4"},
	"kestrel": {LegalName: "Kestrel Insurance Brokers Private Limited", BillingEmail: "accounts@kestrelinsurance.in", AddressLine1: "Office 503, Panchshil Tech Park",
		AddressLine2: "Yerwada", City: "Pune", State: "Maharashtra", PostalCode: "411006", TaxIDType: "gstin", TaxID: "27AAHCK7745P1ZO"},
	"cobalt": {LegalName: "Cobalt Creative Ltd", BillingEmail: "accounts@cobaltcreative.co.uk", AddressLine1: "Unit 4, 23 Charlotte Road",
		AddressLine2: "Shoreditch", City: "London", State: "Greater London", PostalCode: "EC2A 3PB", TaxIDType: "vat", TaxID: "GB284661293"},
}

// subscribe gives the organization its billing details and plan: a trial
// starts as one; a paid plan is invoiced and, unless the story leaves it
// unpaid, paid; a cancelled one ends with its period.
func subscribe(w *world.World, o *world.Org) {
	b, s := w.Deps.Billing.Service, o.Spec
	if p, ok := profiles[s.Slug]; ok {
		p.Country = s.Country
		w.Check(b.UpsertBillingProfile(w.Ctx, o.ID, p), "billing profile of "+s.Slug)
	}
	if s.Billing == "trialing" {
		_, err := b.StartTrial(w.Ctx, o.ID, s.Plan, s.Currency)
		w.Check(err, "start trial "+s.Slug)
		return
	}
	w.Tx("subscribe "+s.Slug, func(tx pgx.Tx) error {
		_, err := b.ChangePlan(w.Ctx, tx, o.ID, s.Plan, s.Currency)
		return err
	})
	if s.Plan == "free" || s.Billing == "unpaid" {
		return
	}
	invoices, err := b.ListInvoices(w.Ctx, o.ID)
	w.Check(err, "invoices of "+s.Slug)
	for _, inv := range invoices {
		if inv.Status == "open" {
			w.Check(b.MarkInvoicePaid(w.Ctx, inv.ID, "pay_"+w.Token(world.Alnum, 14)), "pay the invoice of "+s.Slug)
		}
	}
	if s.Billing == "canceled" {
		w.Tx("cancel "+s.Slug, func(tx pgx.Tx) error { return b.Cancel(w.Ctx, tx, o.ID) })
	}
}

// profile is the directory attributes kept on the account.
func profile(p *world.Person) map[string]any {
	m := map[string]any{"title": p.Title, "employee_id": p.EmployeeID, "location": p.City + ", " + p.Country}
	if p.Department != "" {
		m["department"] = p.Department
	}
	if p.Team != "" {
		m["team"] = p.Team
	}
	if p.Manager != nil {
		m["manager_email"] = p.Manager.Email
	}
	return m
}

// grant gives role its permissions.
func grant(w *world.World, o *world.Org, roleID uuid.UUID, name string, by *world.Person) {
	perms, err := w.Deps.RBAC.Repo.ListPermissions(w.Ctx)
	w.Check(err, "list permissions")
	for _, p := range perms {
		for _, k := range permissions[name] {
			if p.Key == k {
				w.Check(w.Deps.RBAC.Service.GrantPermission(w.Ctx, o.ID, roleID, p.ID, by.Actor()), "grant "+p.Key+" to "+name)
			}
		}
	}
}

// grantGuest invites a person into another organization and accepts it as
// them: a role there can only be given to someone who accepted one.
func grantGuest(w *world.World, p *world.Person, r world.GuestRole) {
	role := r.Org.Roles[r.Role]
	_, token, err := w.Deps.Invite.Service.Create(w.Ctx, invite.CreateInput{OrganizationID: r.Org.ID, Email: p.Email, RoleID: &role}, r.Org.Owner.Actor())
	w.Check(err, "invite guest "+p.Email+" to "+r.Org.Spec.Slug)
	_, err = w.Deps.Invite.Service.AcceptAuthenticated(w.Ctx, p.ID, token, p.Actor())
	w.Check(err, "accept as guest "+p.Email+" in "+r.Org.Spec.Slug)
}

// monogram is an organization's logo: its initials on a rounded square in its
// brand colours, as an SVG data URI (the hosted pages allow only https and
// data: images).
func monogram(name string, b world.Brand) string {
	var initials []rune
	for _, word := range strings.Fields(name) {
		if len(initials) < 2 {
			initials = append(initials, []rune(word)[0])
		}
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">`+
		`<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient></defs>`+
		`<rect width="128" height="128" rx="28" fill="url(#g)"/>`+
		`<text x="64" y="81" text-anchor="middle" font-family="Inter, 'Segoe UI', Helvetica, Arial, sans-serif" font-size="50" font-weight="700" letter-spacing="-2" fill="#FFFFFF">%s</text></svg>`,
		b.Primary, b.Secondary, string(initials))
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}
