package security

import (
	"maps"
	"slices"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
)

// controlOwnerPlans are, for each organization that tracks a framework, which
// part of it answers for each control: security, access (who grants roles),
// engineering (who runs the platform) or audit.
var controlOwnerPlans = map[string]map[string]string{
	"qeet": {
		"CC6.1-MFA": "security", "CC6.1-PWD-LEN": "security", "CC6.1-PWD-CMPLX": "security", "CC6.1-BREACH": "security",
		"CC6.1-SESSION": "engineering", "CC6.3-RBAC-ROLES": "access", "CC6.3-RBAC-ASSIGN": "access", "CC6.5-RETAIN": "audit",
		"A.9.4-MFA": "security", "A.9.2-RBAC": "access", "A.10.1-ENCRYPT": "engineering", "A.12.4.1-AUDIT": "audit", "A.12.4.2-CHAIN": "audit",
	},
	"northwind": {
		"CC6.1-MFA": "security", "CC6.1-SESSION": "security", "CC6.3-RBAC-ASSIGN": "access", "CC6.5-RETAIN": "audit",
		"A.9.4-MFA": "security", "A.9.2-RBAC": "access", "A.12.4.1-AUDIT": "audit",
	},
	"meridian": {
		"CC6.1-MFA": "security", "CC6.1-BREACH": "security", "CC6.3-RBAC-ROLES": "access", "CC6.5-RETAIN": "audit",
	},
	"lumen": {
		"CC6.1-MFA": "engineering", "CC6.3-RBAC-ASSIGN": "access",
	},
}

// controlOwners names who answers for each control, the week the
// organization started tracking its framework, through the evidence service.
func controlOwners(w *world.World) {
	for _, slug := range slices.Sorted(maps.Keys(controlOwnerPlans)) {
		plan := controlOwnerPlans[slug]
		o := org(w, slug)
		if o == nil {
			continue
		}
		at := w.WorkHours(o.Spec.Since.Add(22*day), o.Loc)
		setter := first(o, at, withRole(world.RoleAdmin))
		i := 0
		for _, control := range slices.Sorted(maps.Keys(plan)) {
			p := controlOwner(o, at, plan[control])
			if p == nil {
				continue
			}
			t := at.Add(time.Duration(i*4) * time.Minute)
			i++
			w.At(t, func() {
				w.Check(w.Deps.GDPR.Evidence.SetOwner(w.Ctx, o.ID, control, p.ID, setter.Actor()), "owner of "+control+" at "+slug)
			})
		}
	}
}

// controlOwner is who in o answers for a control in area at t.
func controlOwner(o *world.Org, t time.Time, area string) *world.Person {
	var prefs []func(*world.Person) bool
	switch area {
	case "security":
		prefs = []func(*world.Person) bool{withRole(world.RoleSecurity), inDept("Security"), inDept("Information Security")}
	case "access":
		prefs = []func(*world.Person) bool{withRole(world.RoleITAdmin), withRole(world.RoleAdmin)}
	case "engineering":
		prefs = []func(*world.Person) bool{inDept("Engineering", world.RoleDeveloper), inDept("Technology", world.RoleDeveloper)}
	case "audit":
		prefs = []func(*world.Person) bool{withRole(world.RoleAuditor), withRole(world.RoleSecurity)}
	}
	for _, pref := range prefs {
		if ps := people(o, t, func(p *world.Person) bool { return pref(p) && p.Status == world.StatusActive }); len(ps) > 0 {
			return ps[0]
		}
	}
	return first(o, t, withRole(world.RoleAdmin))
}

// externalAudit is an audit report or certificate an organization recorded.
type externalAudit struct {
	slug, framework, kind, body, scope, reference string
	issued                                        string
	expires                                       string // "" for none
}

// externalAudits are the organizations' external audits. The firms are
// invented; their names belong to no real auditor or certification body.
var externalAudits = []externalAudit{
	{"qeet", "iso27001", "certificate", "Indus Certification Services Pvt. Ltd.",
		"Qeet ID, Qeet Pay and the shared platform they run on: Bengaluru office and AWS ap-south-1.", "ISMS 812044", "2026-03-14", "2029-03-13"},
	{"qeet", "soc2", "audit", "Lakeshore Assurance LLP",
		"SOC 2 Type II, security and availability, 1 February to 31 July 2026: Qeet ID and Qeet Pay.", "QG-SOC2-2026-T2", "2026-09-04", "2027-09-03"},
	{"northwind", "iso27001", "certificate", "Indus Certification Services Pvt. Ltd.",
		"Loan origination, servicing and collections systems; Mumbai head office and the Pune and Thane branches.", "ISMS 790215", "2025-12-05", "2028-12-04"},
	{"northwind", "soc2", "audit", "Lakeshore Assurance LLP",
		"SOC 2 Type I, security, as of 30 June 2026: the borrower portal and loan origination system.", "NWC-SOC2-2026-T1", "2026-08-12", ""},
	{"meridian", "soc2", "audit", "Harbor & Pike CPAs LLP",
		"SOC 2 Type II, security, availability and confidentiality, 1 January to 30 June 2026: the staff portal and clinical integrations.", "MH-2026-0630", "2026-08-28", "2027-08-27"},
}

// recordAudits records each organization's external audits, the week after
// each was issued, as its security or GRC lead.
func recordAudits(w *world.World) {
	for _, a := range externalAudits {
		o := org(w, a.slug)
		if o == nil {
			continue
		}
		issued, err := time.Parse(time.DateOnly, a.issued)
		w.Check(err, "audit date")
		at := w.WorkHours(issued.Add(time.Duration(3+w.Rand.IntN(5))*day), o.Loc)
		if at.After(w.Now) || at.Before(o.Spec.Since) {
			at = w.WorkHours(later(o.Spec.Since.Add(10*day), w.Now.Add(-20*day)), o.Loc)
		}
		by := evidenceOwner(o, at)
		in := gdpr.ExternalAuditInput{Framework: a.framework, Kind: a.kind, Body: a.body, Scope: a.scope, Reference: a.reference, IssuedOn: a.issued}
		if a.expires != "" {
			in.ExpiresOn = &a.expires
		}
		w.At(at, func() {
			_, err := w.Deps.GDPR.Evidence.RecordAudit(w.Ctx, o.ID, in, by.Actor())
			w.Check(err, "record "+a.reference)
		})
	}
}

// incident is a service incident the operator posted for every organization.
type incident struct {
	component, impact, title, detail string
	ago                              float64 // days since it started
	lasted                           time.Duration
}

// incidents are the service's last month, all resolved: what a status page
// keeps in its history.
var incidents = []incident{
	{"api", "maintenance", "Database upgrade", "Planned. The API answered reads throughout; changes waited up to a minute while the database restarted.",
		20.9, 22 * time.Minute},
	{"email", "degraded", "Sign-in codes and invitations delayed",
		"Our email provider held messages for up to 25 minutes. Codes sent during the delay may have expired: ask for a new one.", 9.2, 47 * time.Minute},
	{"webhooks", "degraded", "Webhook deliveries delayed",
		"Deliveries were queued for up to 40 minutes while a dispatcher node was replaced. Every queued delivery was sent; none was lost.", 3.1, 70 * time.Minute},
	{"sign_in", "outage", "Sign-in with Microsoft failing",
		"Microsoft's sign-in service returned errors for accounts in its EU region. Passwords, passkeys and other providers worked.", 15.4, 34 * time.Minute},
}

// statusIncidents posts the service's resolved incidents.
func statusIncidents(w *world.World) {
	ist := world.Location("Asia/Kolkata")
	for _, in := range incidents {
		started := w.WorkHours(w.Days(in.ago), ist)
		if in.impact == "maintenance" {
			started = localTime(w.Days(in.ago), ist, 1, 30)
		}
		w.Exec("incident "+in.title, `INSERT INTO platform.incidents (component, impact, title, detail, started_at, resolved_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, in.component, in.impact, in.title, in.detail, started, started.Add(in.lasted))
	}
}

// later is the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
