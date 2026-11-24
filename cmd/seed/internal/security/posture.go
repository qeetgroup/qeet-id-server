package security

import (
	"maps"
	"slices"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance"
	"github.com/qeetgroup/qeet-id-server/internal/operations/sales"
)

// rule is an address rule as an administrator types it.
type rule struct{ cidr, label, action string }

// addressRules writes the organization's address rules in the console, in
// three states: Northwind enforces deny rules only, so localhost signs in;
// Kestrel enforces an office allowlist, so localhost is refused; Qeet keeps
// an allowlist staged, switched off. Ranges are RFC 5737.
func addressRules(w *world.World, o *world.Org) {
	var rules []rule
	enforce := true
	by := o.First(world.HasRole(world.RoleSecurity), world.InDept("Security"), world.HasRole(world.RoleAdmin))
	switch o.Spec.Slug {
	case "northwind":
		rules = []rule{
			{"192.0.2.240/29", "Credential-stuffing proxies (threat-intel feed, SOC-2026-014)", "deny"},
			{"198.51.100.232/29", "Anonymising VPN exit nodes", "deny"},
			{"203.0.113.248/29", "Tor exit relays (weekly feed)", "deny"},
			{"203.0.113.0/29", "Bulletproof hosting range (CERT-In advisory CIAD-2026-0007)", "deny"},
			{"198.51.100.253/32", "Scanner flagged by Splunk ES (notable 48213)", "deny"},
		}
	case "kestrel":
		seen := map[string]bool{}
		for _, p := range o.People {
			for _, c := range world.India.Cities {
				if c.Name == p.City && !seen[c.Name] {
					seen[c.Name] = true
					rules = append(rules, rule{c.Office + "/32", c.Name + " branch office", "allow"})
				}
				if c.Name == p.City && p == o.Owner {
					// The owner works from the office, so switching the rules on
					// doesn't lock him out; the others sign in from home.
					p.Device.IP = c.Office
				}
			}
		}
		rules = append(rules, rule{"203.0.113.236/32", "Office VPN — FortiGate SSL-VPN (head office)", "allow"},
			rule{"203.0.113.237/32", "Head office guest Wi-Fi", "deny"})
		by = o.Owner
	case "qeet":
		rules = []rule{
			{"203.0.113.10/32", "Bengaluru HQ — HSR Layout (ACT Fibernet)", "allow"},
			{"192.0.2.10/32", "Berlin — co-working desk (Kreuzberg)", "allow"},
			{"203.0.113.238/32", "Corporate VPN — WireGuard gateway (ap-south-1)", "allow"},
			{"192.0.2.244/30", "Credential-stuffing proxies (threat-intel feed)", "deny"},
		}
		enforce, by = false, o.Person("priya@qeet.in")
	default:
		return
	}
	path := "/organizations/" + o.ID.String() + "/ip-rules"
	for _, r := range rules {
		w.API.Do(o, by, "POST", path, map[string]any{"cidr": r.cidr, "label": r.label, "action": r.action}, nil)
	}
	if enforce {
		w.API.Do(o, by, "PUT", path+"/config", map[string]any{"enabled": true}, nil)
	}
}

// riskSpec is an organization's adaptive-risk and bot settings.
type riskSpec struct {
	slug string
	risk risk.Settings
	bot  bot.Settings
}

var riskSpecs = []riskSpec{
	{"qeet", risk.Settings{MediumThreshold: 0.5, HighThreshold: 0.8, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: true, MinTravelHours: 3, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.7}},
	{"northwind", risk.Settings{MediumThreshold: 0.4, HighThreshold: 0.7, ForceMFAAtLevel: "medium",
		ImpossibleTravelEnabled: true, MinTravelHours: 2, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, Signature: true, ScoreThreshold: 0.6}},
	{"meridian", risk.Settings{MediumThreshold: 0.5, HighThreshold: 0.75, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: true, MinTravelHours: 4, DeviceReputationEnabled: false},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: false, ScoreThreshold: 0.7}},
	{"lumen", risk.Settings{MediumThreshold: 0.55, HighThreshold: 0.85, ForceMFAAtLevel: "high",
		ImpossibleTravelEnabled: false, MinTravelHours: 3, DeviceReputationEnabled: true},
		bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.8}},
	{"aster", risk.Settings{}, bot.Settings{UACheck: true, Honeypot: true, Captcha: true, ScoreThreshold: 0.7}},
}

// anomalySettings are the organizations that tuned audit-anomaly scoring.
var anomalySettings = map[string]map[string]any{
	"northwind": {"enabled": true, "score_threshold": 0.55, "min_baseline_events": 25},
	"qeet":      {"enabled": true, "score_threshold": 0.6, "min_baseline_events": 20},
	"meridian":  {"enabled": true, "score_threshold": 0.65, "min_baseline_events": 30},
	"kestrel":   {"enabled": false, "score_threshold": 0.6, "min_baseline_events": 20},
}

// threatSettings stores the organization's risk and bot settings through
// their services, and its anomaly settings in the console.
func threatSettings(w *world.World, o *world.Org) {
	by := o.First(world.HasRole(world.RoleSecurity), world.HasRole(world.RoleAdmin))
	for _, s := range riskSpecs {
		if s.slug != o.Spec.Slug {
			continue
		}
		if s.risk.HighThreshold > 0 {
			_, err := w.Deps.Risk.Service.UpdateSettings(w.Ctx, o.ID, s.risk, by.Actor())
			w.Check(err, "risk settings for "+s.slug)
		}
		_, err := w.Deps.Bot.Service.UpdateSettings(w.Ctx, o.ID, s.bot, by.Actor())
		w.Check(err, "bot settings for "+s.slug)
	}
	if a, ok := anomalySettings[o.Spec.Slug]; ok {
		w.API.Do(o, by, "PUT", "/organizations/"+o.ID.String()+"/audit/anomaly-settings", a, nil)
	}
}

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

// evidence names who answers for each control, records each organization's
// external audits and generates its evidence through the evidence service,
// and posts the service's resolved incidents.
func evidence(w *world.World) {
	ev := w.Deps.Compliance.Evidence
	for _, slug := range slices.Sorted(maps.Keys(controlOwnerPlans)) {
		o := w.Org(slug)
		admin := o.First(world.HasRole(world.RoleAdmin))
		owners := map[string]*world.Person{
			"security":    o.First(world.HasRole(world.RoleSecurity), world.InDept("Security"), world.InDept("Information Security")),
			"access":      o.First(world.HasRole(world.RoleITAdmin), world.HasRole(world.RoleAdmin)),
			"engineering": o.First(world.HasRole(world.RoleDeveloper)),
			"audit":       o.First(world.HasRole(world.RoleAuditor), world.HasRole(world.RoleSecurity)),
		}
		plan := controlOwnerPlans[slug]
		for _, control := range slices.Sorted(maps.Keys(plan)) {
			w.Check(ev.SetOwner(w.Ctx, o.ID, control, owners[plan[control]].ID, admin.Actor()), "owner of "+control+" at "+slug)
		}
		for _, fw := range []string{"soc2", "iso27001"} {
			_, err := ev.Generate(w.Ctx, o.ID, fw, owners["audit"].Actor())
			w.Check(err, "generate "+fw+" evidence for "+slug)
		}
	}
	for _, a := range externalAudits {
		o := w.Org(a.slug)
		in := compliance.ExternalAuditInput{Framework: a.framework, Kind: a.kind, Body: a.body, Scope: a.scope, Reference: a.reference, IssuedOn: a.issued}
		if a.expires != "" {
			in.ExpiresOn = &a.expires
		}
		_, err := ev.RecordAudit(w.Ctx, o.ID, in, o.First(world.HasRole(world.RoleSecurity), world.HasRole(world.RoleAdmin)).Actor())
		w.Check(err, "record "+a.reference)
	}
	for _, in := range [][3]string{
		{"email", "Sign-in codes and invitations delayed", "Our email provider held messages for up to 25 minutes. Codes sent during the delay may have expired: ask for a new one."},
		{"webhooks", "Webhook deliveries delayed", "Deliveries were queued for up to 40 minutes while a dispatcher node was replaced. Every queued delivery was sent; none was lost."},
	} {
		id, err := w.Deps.ServiceHealth.Service.OpenIncident(w.Ctx, in[0], "degraded", in[1], in[2])
		w.Check(err, "incident "+in[1])
		w.Check(w.Deps.ServiceHealth.Service.ResolveIncident(w.Ctx, id), "resolve "+in[1])
	}
}

// lead is a "Contact sales" submission: from a customer's owner on the
// billing page, or from a prospect choosing a plan during onboarding.
// Prospects' domains are unregistered.
type lead struct{ slug, email, name, company, teamSize, message string }

var leads = []lead{
	{"lumen", "jonas.becker@lumenlabshq.dev", "", "", "11-50",
		"We're outgrowing Pro. We need SCIM from Google Workspace, EU data residency for our customer organizations and a 99.99% SLA before our Series B security review."},
	{"vertex", "tyler.morgan@vertexfreightco.us", "", "", "11-50",
		"Trial is going well. We need Okta SCIM and SSO enforcement for our dispatch floor — can we get an Enterprise quote before the trial ends?"},
	{"", "ritika.bose@brightwaterclinics.in", "Ritika Bose", "Brightwater Clinics", "200+",
		"Hospital chain, 11 sites, moving off on-prem Active Directory. Need LDAP and SAML side by side for 18 months, audit export for NABH, and data in ap-south-1."},
	{"", "tanvi.joshi@orbitalpayments.io", "Tanvi Joshi", "Orbital Payments", "11-50",
		"PCI-DSS scoped platform. Need RBAC plus ABAC, machine-to-machine tokens for 30 services, and your SOC 2 Type II report."},
}

// salesLeads submits the leads through the sales service; a customer's lead
// carries its organization and owner.
func salesLeads(w *world.World) {
	for _, l := range leads {
		in := sales.Lead{Name: l.name, Email: l.email, Company: l.company, TeamSize: l.teamSize, Message: l.message, Source: "onboarding"}
		var organization, user *uuid.UUID
		if o := w.Org(l.slug); o != nil {
			p := o.Person(l.email)
			in.Name, in.Company, in.Source = p.Name(), o.Spec.Name, "billing"
			organization, user = &o.ID, &p.ID
		}
		w.Check(w.Deps.Sales.Service.Submit(w.Ctx, organization, user, in), "sales lead from "+l.email)
	}
}
