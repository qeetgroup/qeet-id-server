// Package census creates the seeded organizations: their owners, plans, roles,
// groups and people. It also decides each person's story — when they joined,
// whether they left or were suspended, which second factors they use, which
// accounts are for testers — which the later steps carry out.
package census

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// Seed plans and creates every organization, in the order they signed up.
func Seed(w *world.World) {
	for _, s := range specs(w) {
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
	}
	for _, o := range w.Orgs {
		w.Note("Organisations", "%-26s %-11s %-10s %3d people   %s", o.Spec.Name, o.Spec.Plan+billingNote(o.Spec), o.Spec.Region, len(o.People), o.Spec.Domain)
	}
}

func billingNote(s world.OrgSpec) string {
	if s.Billing == "active" {
		return ""
	}
	return "·" + s.Billing
}

// Org returns the seeded organization with slug; it panics if there is none.
func Org(w *world.World, slug string) *world.Org {
	for _, o := range w.Orgs {
		if o.Spec.Slug == slug {
			return o
		}
	}
	panic("seed: no organisation " + slug)
}

// fixed is a person whose name and address testers rely on.
type fixed struct {
	email, first, last, title, dept, team, role, login string
}

// named are each organization's fixed people; the first is its owner. The
// rest of every roster is generated.
var named = map[string][]fixed{
	"qeet": {
		{"saibabu@qeet.in", "Mareedu", "Saibabu", "Founder & CEO", "", "", world.RoleOwner, "Owner of Qeet Group and Qeet Sandbox (organisation picker)"},
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
		{"oliver.bennett@cobaltcreative.co.uk", "Oliver", "Bennett", "Founding Partner", "", "", world.RoleOwner, "Owner — cancelled Starter, now Free"},
		{"poppy.clarke@cobaltcreative.co.uk", "Poppy", "Clarke", "Partner", "", "", world.RoleOwner, ""},
		{"rory.campbell@cobaltcreative.co.uk", "Rory", "Campbell", "Partner", "", "", world.RoleOwner, ""},
	},
	"fjord": {
		{"ingrid.solberg@fjordanalytics.no", "Ingrid", "Solberg", "Founder", "", "", world.RoleOwner, "Owner — new organisation, onboarding checklist open"},
	},
}

// plan decides the organization's people without touching the database.
func plan(w *world.World, s world.OrgSpec) *world.Org {
	o := &world.Org{Spec: s, Roles: map[string]uuid.UUID{}, Groups: map[string]uuid.UUID{}, Loc: world.Location(s.TimeZone)}
	used := map[string]bool{}
	home := s.Locales[0]

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
		p := &world.Person{
			Org: o, First: first, Last: last, Email: email, City: city.Name, Country: l.Country,
			Loc: world.Location(city.TZ), Status: world.StatusActive,
		}
		if w.Chance(0.75) {
			p.Phone = l.Phone(w)
		}
		p.Device = w.NewDevice(l, city, "desktop")
		p.Mobile = w.NewDevice(l, city, "mobile")
		used[email] = true
		return p
	}

	// The fixed people first, the owner at their head.
	for _, f := range named[s.Slug] {
		l := home
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
	}
	for _, d := range s.Depts {
		if heads[d.Name] == nil && len(o.People) < s.Size {
			p := generated(w, o, newPerson, used)
			p.Title, p.Department, p.Role = d.Head, d.Name, headRole(d)
			heads[d.Name] = p
			o.People = append(o.People, p)
		}
	}
	for i := 0; len(o.People) < s.Size && total > 0; i++ {
		d := pickDept(w, s.Depts, total)
		p := generated(w, o, newPerson, used)
		p.Department, p.Role = d.Name, d.Role
		p.Title = world.Pick(w, d.Titles)
		p.Team = d.Teams[i%len(d.Teams)]
		o.People = append(o.People, p)
	}
	// Teams with a fixed member have that member; everyone else's team is set.
	for _, p := range o.People {
		if p.Department != "" && p.Team == "" && heads[p.Department] != p {
			for _, d := range s.Depts {
				if d.Name == p.Department {
					p.Team = d.Teams[0]
				}
			}
		}
	}
	// Managers: a team's first member leads it and reports to the department
	// head; the rest report to the lead.
	leads := map[string]*world.Person{}
	for _, p := range o.People {
		if p == o.Owner {
			continue
		}
		if heads[p.Department] == p {
			if p != o.Owner {
				p.Manager = o.Owner
			}
			continue
		}
		key := p.Department + "/" + p.Team
		if leads[key] == nil {
			leads[key] = p
			p.Manager = heads[p.Department]
			continue
		}
		p.Manager = leads[key]
	}
	if s.Slug == "qeet" {
		for _, p := range o.People {
			if p.Department == "" && p != o.Owner {
				p.Manager = o.Owner
			}
		}
	}

	joinDates(w, o)
	for i, p := range o.People {
		p.EmployeeID = fmt.Sprintf("%s-%04d", strings.ToUpper(s.Slug[:3]), 1001+i)
		p.Activity = activity(w, p)
	}
	provisioning(w, o)
	lifecycle(w, o)
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

// generated is a new person with a unique first.last address at the
// organization's domain.
func generated(w *world.World, o *world.Org, newPerson func(world.Locale, string, string, string) *world.Person, used map[string]bool) *world.Person {
	for {
		l := world.Pick(w, o.Spec.Locales)
		first, last := world.Pick(w, l.First), world.Pick(w, l.Last)
		email := world.EmailLocal(first, last) + "@" + o.Spec.Domain
		if !used[email] && !taken[email] {
			taken[email] = true
			return newPerson(l, first, last, email)
		}
	}
}

// taken is every address generated so far, across organizations.
var taken = map[string]bool{}

// joinDates spreads people over the organization's life: the owner on day
// one, heads in the first fortnight, most of the rest in the first six weeks'
// roll-out, and a steady trickle of hires since — some in the last month.
func joinDates(w *world.World, o *world.Org) {
	since := o.Spec.Since
	age := w.Now.Sub(since)
	rollout := since.Add(45 * 24 * time.Hour)
	if rollout.After(w.Now) {
		rollout = w.Now.Add(-time.Hour)
	}
	for i, p := range o.People {
		switch {
		case i == 0:
			p.Joined = since
		case p.Manager == o.Owner || p.Login != "":
			p.Joined = since.Add(time.Duration(w.Rand.Int64N(int64(min(age, 14*24*time.Hour)/2) + 1)))
		case w.Chance(0.6):
			p.Joined = w.Between(since.Add(time.Hour), rollout)
		default:
			p.Joined = w.Between(since.Add(time.Hour), w.Now.Add(-2*time.Hour))
		}
		p.Joined = w.WorkHours(p.Joined, o.Loc)
		if p.Joined.Before(since) {
			p.Joined = since.Add(time.Duration(i+1) * time.Minute)
		}
		if p.Joined.After(w.Now) {
			p.Joined = w.Now.Add(-time.Duration(i+1) * time.Hour)
		}
	}
	// Creation order is join order, owner first.
	sort.SliceStable(o.People[1:], func(i, j int) bool { return o.People[1+i].Joined.Before(o.People[1+j].Joined) })
}

// activity is how often a person signs in on a working day.
func activity(w *world.World, p *world.Person) float64 {
	base := 0.8
	switch p.Role {
	case world.RoleOwner, world.RoleAdmin, world.RoleITAdmin, world.RoleSecurity, world.RoleHelpdesk:
		base = 1.6
	case world.RoleDeveloper:
		base = 1.3
	case world.RoleAuditor, world.RoleBilling:
		base = 0.4
	}
	if p.Department == "Clinical Operations" || p.Department == "Warehouse" {
		base = 0.6
	}
	return base * (0.6 + 0.8*w.Rand.Float64())
}

// provisioning marks who arrived from a directory: everyone but the owner where
// SCIM pushes accounts, and clinical staff from Meridian's on-premises
// directory.
func provisioning(w *world.World, o *world.Org) {
	for _, p := range o.People[1:] {
		switch {
		case o.Spec.Features.LDAP && p.Department == "Clinical Operations":
			p.Provisioned = "ldap"
			p.ExternalID = fmt.Sprintf("CN=%s %s,OU=Clinical,OU=Staff,DC=corp,DC=meridianhealth,DC=us", p.First, p.Last)
		case o.Spec.Features.SCIM:
			p.Provisioned = "scim"
			if o.Spec.Features.SSO == "okta" {
				p.ExternalID = "00u" + randomID(w, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 17)
			} else {
				p.ExternalID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.Email)).String()
			}
		}
	}
}

func randomID(w *world.World, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[w.Rand.IntN(len(alphabet))]
	}
	return string(b)
}

// lifecycle decides who left and who is suspended (about one in twenty-five
// each, among people there for two months or more), and who never verified
// their address (one recent joiner in each larger organization).
func lifecycle(w *world.World, o *world.Org) {
	if len(o.People) < 12 {
		return
	}
	var veterans, recent []*world.Person
	for _, p := range o.People[1:] {
		if p.Login != "" || p.Manager == o.Owner {
			continue
		}
		if p.Joined.Before(w.Days(60)) {
			veterans = append(veterans, p)
		} else if p.Provisioned == "" {
			recent = append(recent, p)
		}
	}
	w.Rand.Shuffle(len(veterans), func(i, j int) { veterans[i], veterans[j] = veterans[j], veterans[i] })
	leavers := max(1, len(o.People)/25)
	suspended := max(1, len(o.People)/25)
	reasons := []string{"offboarding", "suspicious_activity", "inactive", "policy_violation"}
	for i, p := range veterans {
		switch {
		case i < leavers:
			p.Status, p.Since = world.StatusDeleted, w.Between(w.Days(40), w.Days(3))
		case i < leavers+suspended:
			p.Status, p.Since = world.StatusSuspended, w.Between(w.Days(30), w.Days(1))
			p.Reason = reasons[(i-leavers)%len(reasons)]
			switch {
			case p.Provisioned == "scim" && p.Reason == "offboarding":
				p.Source = "scim"
			case p.Provisioned == "ldap":
				p.Source = "ldap"
			case p.Reason == "inactive":
				p.Source = "policy"
			default:
				p.Source = "manual"
			}
		}
	}
	if len(recent) > 0 {
		recent[len(recent)-1].Unverified = true
	}
}

// factors decides each person's second factors from the organization's MFA
// policy: everyone where it is required, administrators where only they must,
// and the security-minded few where it's optional.
func factors(w *world.World, o *world.Org) {
	sms := o.Has("starter")
	for _, p := range o.People {
		admin := p.Role == world.RoleOwner || p.Role == world.RoleAdmin || p.Role == world.RoleITAdmin || p.Role == world.RoleSecurity
		var adopt float64
		switch o.Spec.Features.MFA {
		case "required":
			adopt = 1
		case "admin_only":
			adopt = 0.25
			if admin {
				adopt = 1
			}
		default:
			adopt = 0.3
			if o.Spec.Industry != "" && strings.HasPrefix(o.Spec.Industry, "Software") {
				adopt = 0.7
			}
		}
		if !w.Chance(adopt) {
			continue
		}
		switch r := w.Rand.Float64(); {
		case r < 0.55:
			p.MFA = []string{"totp", "recovery"}
		case r < 0.75 && o.Spec.Features.Passkeys:
			p.MFA = []string{"passkey", "totp", "recovery"}
		case r < 0.85:
			p.MFA = []string{"push", "totp", "recovery"}
		case r < 0.93 && sms && p.Phone != "":
			p.MFA = []string{"sms"}
		default:
			p.MFA = []string{"email"}
		}
		lag := time.Duration(w.Rand.Int64N(int64(20 * 24 * time.Hour)))
		if o.Spec.Features.MFA == "optional" {
			lag = time.Duration(w.Rand.Int64N(int64(max(w.Now.Sub(p.Joined), time.Hour))))
		}
		p.MFASince = p.Joined.Add(lag)
		if p.MFASince.After(w.Now) {
			p.MFASince = w.Now.Add(-time.Hour)
		}
	}
	// Fixed choices testers rely on.
	if o.Spec.Slug == "qeet" {
		o.Owner.MFA = nil // the founder signs in with a password alone
		if a := o.Person("aarav@qeet.in"); a != nil {
			a.MFA, a.MFASince = []string{"totp", "recovery"}, a.Joined.Add(48*time.Hour)
		}
		for _, e := range []string{"rohan@qeet.in", "sneha@qeet.in", "vikram@qeet.in", "grace@qeet.in", "priya@qeet.in"} {
			if p := o.Person(e); p != nil {
				p.MFA = nil
			}
		}
	}
	if o.Spec.Features.MFA == "required" && len(o.People) > 1 {
		o.Owner.MFA, o.Owner.MFASince = []string{"totp", "recovery"}, o.Owner.Joined.Add(time.Hour)
	}
}

// addGuests gives a few people roles in organizations other than their own.
func addGuests(w *world.World) {
	guest := func(email, homeSlug, slug, role string, since time.Time) {
		p := Org(w, homeSlug).Person(email)
		o := Org(w, slug)
		p.GuestOf = append(p.GuestOf, world.GuestRole{Org: o, Role: role, Since: since})
		o.Guests = append(o.Guests, p)
	}
	sandbox := Org(w, "qeet-sandbox")
	sandbox.Owner = Org(w, "qeet").Owner
	guest("priya@qeet.in", "qeet", "qeet-sandbox", world.RoleOwner, sandbox.Spec.Since.Add(3*24*time.Hour))
	guest("grace@qeet.in", "qeet", "northwind", world.RoleHelpdesk, Org(w, "northwind").Spec.Since.Add(2*24*time.Hour))
	guest("lucia.garcia@lumenlabshq.dev", "lumen", "aster", world.RoleDeveloper, Org(w, "aster").Spec.Since.Add(10*24*time.Hour))
}

// permissions are each role's grants. Admin and the owner hold everything.
var permissions = map[string][]string{
	world.RoleITAdmin: {"tenant.read", "user.read", "user.write", "user.delete", "user.suspend", "user.credentials", "session.revoke",
		"member.invite", "group.read", "group.write", "role.read", "role.write",
		"connection.read", "connection.write", "policy.read", "policy.write", "branding.write", "audit.read", "analytics.read"},
	world.RoleHelpdesk: {"tenant.read", "user.read", "user.write", "user.suspend", "user.credentials", "session.revoke",
		"group.read", "role.read", "audit.read"},
	world.RoleSecurity: {"tenant.read", "user.read", "group.read", "role.read", "audit.read", "audit.write", "analytics.read",
		"policy.read", "policy.write", "connection.read", "secret.read", "webhook.read", "apikey.read"},
	world.RoleAuditor: {"tenant.read", "user.read", "group.read", "role.read", "audit.read", "analytics.read", "policy.read",
		"connection.read", "apikey.read", "webhook.read", "billing.read"},
	world.RoleDeveloper: {"tenant.read", "user.read", "group.read", "role.read", "apikey.read", "apikey.write",
		"webhook.read", "webhook.write", "secret.read", "secret.write", "connection.read", "analytics.read"},
	world.RoleBilling: {"tenant.read", "billing.read", "billing.write", "user.read"},
	world.RoleMember:  {"tenant.read", "user.read", "role.read", "group.read"},
}

var roleDescriptions = map[string]string{
	world.RoleAdmin:     "Full administrative access to the organisation",
	world.RoleITAdmin:   "Manages people, groups, connections and sign-in policy",
	world.RoleHelpdesk:  "Helps people sign in: resets, unlocks and profile changes",
	world.RoleSecurity:  "Investigates sign-in activity and manages security policy",
	world.RoleAuditor:   "Reads everything for audits; changes nothing",
	world.RoleDeveloper: "Builds integrations: API keys, webhooks, secrets and applications",
	world.RoleBilling:   "Manages the subscription, invoices and payment details",
	world.RoleMember:    "Standard access: sees the directory, changes nothing",
}

// create writes the organization: owner and organization on its first day, the plan,
// roles and groups that afternoon, then each person on the day they joined.
func create(w *world.World, o *world.Org) {
	ctx, d := w.Ctx, w.Deps
	s := o.Spec
	owner := o.Owner
	w.At(s.Since, func() {
		if owner.Org == o {
			_, u, _, err := d.Auth.Service.Signup(ctx, auth.SignupInput{
				Email: owner.Email, Password: w.Password, DisplayName: owner.Name(),
				IP: owner.Device.IP, UserAgent: owner.Device.UserAgent,
			})
			w.Check(err, "sign up "+owner.Email)
			owner.ID = u.ID
			w.Check(d.User.Repo.MarkEmailVerified(ctx, u.ID), "verify "+owner.Email)
		}
		t, err := d.Organization.Repo.CreateWithOwner(ctx, organization.CreateInput{
			Slug: s.Slug, Name: s.Name, Plan: s.Plan, Region: s.Region,
			Metadata: map[string]any{"industry": s.Industry, "headquarters": s.City + ", " + s.Country, "website": "https://" + s.Domain},
		}, owner.ID)
		w.Check(err, "create organisation "+s.Slug)
		o.ID, o.Organization = t.ID, t
		w.Audit(s.Since, audit.Event{OrganizationID: &o.ID, ActorUserID: &owner.ID, Action: "tenant.created", ResourceType: "tenant",
			ResourceID: &o.ID, IP: owner.Device.IP, UserAgent: owner.Device.UserAgent, Metadata: map[string]any{"name": s.Name, "plan": s.Plan}})
	})
	if owner.Org == o {
		w.Exec("profile "+owner.Email, `UPDATE account.users SET phone = NULLIF($2, ''), metadata = $3 WHERE id = $1 AND organization_id = $4`,
			owner.ID, owner.Phone, profile(owner), o.ID)
	}
	// The plan: a trial starts as one; everything else as its paid plan.
	w.At(s.Since.Add(20*time.Minute), func() {
		if s.Billing == "trialing" {
			_, err := d.Billing.Service.StartTrial(ctx, o.ID, s.Plan, s.Currency)
			w.Check(err, "start trial "+s.Slug)
			return
		}
		w.Tx("subscribe "+s.Slug, func(tx pgx.Tx) error {
			_, err := d.Billing.Service.ChangePlan(ctx, tx, o.ID, s.Plan, s.Currency)
			return err
		})
	})

	// A trial ends fourteen days after it started, not after the seed ran.
	if s.Billing == "trialing" {
		w.Exec("date the trial of "+s.Slug, `UPDATE organization.subscriptions SET trial_end = $2, current_period_end = $2
			WHERE organization_id = $1 AND status = 'trialing'`, o.ID, s.Since.Add(20*time.Minute+14*24*time.Hour))
	}

	// Roles: the ones its people hold, plus Admin, Auditor and Member.
	if o.Has("starter") {
		w.At(s.Since.Add(40*time.Minute), func() {
			want := map[string]bool{world.RoleAdmin: true, world.RoleMember: true}
			if len(o.People) >= 20 {
				want[world.RoleAuditor] = true
			}
			for _, p := range o.People {
				want[p.Role] = true
			}
			for _, g := range o.Guests {
				for _, r := range g.GuestOf {
					if r.Org == o {
						want[r.Role] = true
					}
				}
			}
			for _, name := range []string{world.RoleAdmin, world.RoleITAdmin, world.RoleSecurity, world.RoleHelpdesk,
				world.RoleDeveloper, world.RoleAuditor, world.RoleBilling, world.RoleMember} {
				if !want[name] {
					continue
				}
				// Every organization has built-in admin and member roles.
				if builtin, ok := builtinRoles[name]; ok {
					o.Roles[name] = systemRole(w, o, builtin)
					continue
				}
				r, err := d.RBAC.Service.CreateRole(ctx, o.ID, name, roleDescriptions[name], owner.Actor())
				w.Check(err, "role "+name+" in "+s.Slug)
				o.Roles[name] = r.ID
				grant(w, o, r.ID, name, owner)
			}
		})
	}
	o.Roles[world.RoleOwner] = ownerRole(w, o)

	// Groups: a group per department, a nested group per team.
	if len(s.Depts) > 0 {
		w.At(s.Since.Add(time.Hour), func() {
			for _, dpt := range s.Depts {
				g, err := d.Group.Service.Create(ctx, group.CreateInput{OrganizationID: o.ID, Name: dpt.Name,
					Description: "Everyone in " + dpt.Name}, owner.Actor())
				w.Check(err, "group "+dpt.Name)
				o.Groups[dpt.Name] = g.ID
				parent := g.ID
				for _, team := range dpt.Teams {
					tg, err := d.Group.Service.Create(ctx, group.CreateInput{OrganizationID: o.ID, ParentID: &parent, Name: team,
						Description: dpt.Name + " — " + team}, owner.Actor())
					w.Check(err, "group "+team)
					o.Groups[team] = tg.ID
				}
			}
		})
	}

	// People, each on the day they joined, added by the owner or by their
	// identity provider.
	for _, p := range o.People {
		if p == owner {
			addToGroups(w, o, p, owner)
			continue
		}
		by := admin(o, p.Joined)
		w.At(p.Joined, func() {
			u, err := d.User.Repo.CreateWithCredential(ctx, user.CreateInput{
				OrganizationID: o.ID, Email: p.Email, DisplayName: p.Name(), Phone: p.Phone, Metadata: profile(p),
			}, w.PasswordHash)
			w.Check(err, "create "+p.Email)
			p.ID = u.ID
			if !p.Unverified {
				w.Check(d.User.Repo.MarkEmailVerified(ctx, u.ID), "verify "+p.Email)
			}
			actor := by.Actor()
			if p.Provisioned == "scim" || p.Provisioned == "ldap" {
				actor = world.System
				actor.Type = p.Provisioned
			}
			w.Check(d.RBAC.Service.AssignRole(ctx, u.ID, o.ID, o.Roles[p.Role], &by.ID, actor), "assign "+p.Email)
			addToGroups(w, o, p, by)
			w.Audit(p.Joined, audit.Event{OrganizationID: &o.ID, ActorUserID: actor.UserID, ActorType: actor.Type, Action: "user.created",
				ResourceType: "user", ResourceID: &p.ID, IP: actor.IP, UserAgent: actor.UserAgent,
				Metadata: map[string]any{"email": p.Email, "source": source(p)}})
		})
		if p.Provisioned != "" {
			w.Exec("provisioned "+p.Email, `UPDATE account.users SET provisioned_via = $2, external_id = $3 WHERE id = $1 AND organization_id = $4`,
				p.ID, p.Provisioned, p.ExternalID, o.ID)
		}
	}
}

func source(p *world.Person) string {
	if p.Provisioned != "" {
		return p.Provisioned
	}
	return "admin"
}

// admin is who added someone joining at t: the owner at first, later an IT
// administrator when there is one.
func admin(o *world.Org, t time.Time) *world.Person {
	for _, p := range o.People {
		if (p.Role == world.RoleITAdmin || p.Role == world.RoleAdmin) && p.ID != uuid.Nil && settled(p, t) {
			return p
		}
	}
	return o.Owner
}

// settled reports whether p had been there a week by t.
func settled(p *world.Person, t time.Time) bool { return t.Sub(p.Joined) > 7*24*time.Hour }

// addToGroups puts p in their team's group, or their department's when they
// lead it.
func addToGroups(w *world.World, o *world.Org, p, by *world.Person) {
	name := p.Team
	if name == "" {
		name = p.Department
	}
	g, ok := o.Groups[name]
	if !ok {
		return
	}
	w.Check(w.Deps.Group.Service.AddMember(w.Ctx, g, p.ID, o.ID, by.Actor()), "group member "+p.Email)
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

// grant gives role its permissions; Admin gets every permission there is.
func grant(w *world.World, o *world.Org, roleID uuid.UUID, name string, by *world.Person) {
	perms, err := w.Deps.RBAC.Repo.ListPermissions(w.Ctx)
	w.Check(err, "list permissions")
	keys := map[string]bool{}
	for _, k := range permissions[name] {
		keys[k] = true
	}
	for _, p := range perms {
		if name == world.RoleAdmin || keys[p.Key] {
			w.Check(w.Deps.RBAC.Service.GrantPermission(w.Ctx, o.ID, roleID, p.ID, by.Actor()), "grant "+p.Key+" to "+name)
		}
	}
}

// ownerRole is the organization's system owner role.
func ownerRole(w *world.World, o *world.Org) uuid.UUID { return systemRole(w, o, "owner") }

// builtinRoles are the seed's roles every organization has built in, by the
// built-in role's name.
var builtinRoles = map[string]string{world.RoleAdmin: "admin", world.RoleMember: "member"}

// systemRole is the organization's built-in role called name.
func systemRole(w *world.World, o *world.Org, name string) uuid.UUID {
	var id uuid.UUID
	w.Check(w.Admin.QueryRow(w.Ctx, `SELECT id FROM rbac.roles WHERE organization_id = $1 AND is_system AND name = $2`, o.ID, name).Scan(&id), name+" role of "+o.Spec.Slug)
	return id
}

// grantGuest invites a person into another organization and accepts it as
// them: a role there can only be given to someone who accepted one.
func grantGuest(w *world.World, p *world.Person, r world.GuestRole) {
	w.At(r.Since, func() {
		by := r.Org.Owner
		role := r.Org.Roles[r.Role]
		_, token, err := w.Deps.Invite.Service.Create(w.Ctx, invite.CreateInput{OrganizationID: r.Org.ID, Email: p.Email, RoleID: &role}, by.Actor())
		w.Check(err, "invite guest "+p.Email+" to "+r.Org.Spec.Slug)
		_, err = w.Deps.Invite.Service.AcceptAuthenticated(w.Ctx, p.ID, token, p.Actor())
		w.Check(err, "accept as guest "+p.Email+" in "+r.Org.Spec.Slug)
	})
}
