package activity

import (
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/sales"
)

// lead is a "Contact sales" submission: from a customer's owner on the
// billing page, or from someone still choosing a plan during onboarding.
type lead struct {
	slug, email   string // slug: the customer organization it came from, if any
	name, company string
	teamSize      string
	message       string
	daysAgo       float64
}

// leads are the enterprise prospects. Prospects' domains are unregistered.
var leads = []lead{
	{"lumen", "jonas.becker@lumenlabshq.dev", "", "", "11-50",
		"We're outgrowing Pro. We need SCIM from Google Workspace, EU data residency for our customer tenants and a 99.99% SLA before our Series B security review.", 24},
	{"aster", "meera.shetty@asterretail.in", "", "", "11-50",
		"Opening 14 stores this year. Looking at SSO with Google Workspace for store and warehouse staff, and whether Enterprise pricing works for ~200 seasonal accounts.", 12},
	{"vertex", "tyler.morgan@vertexfreightco.us", "", "", "11-50",
		"Trial is going well. We need Okta SCIM and SSO enforcement for our dispatch floor — can we get an Enterprise quote before the trial ends?", 2},
	{"", "ritika.bose@brightwaterclinics.in", "Ritika Bose", "Brightwater Clinics", "200+",
		"Hospital chain, 11 sites, moving off on-prem Active Directory. Need LDAP and SAML side by side for 18 months, audit export for NABH, and data in ap-south-1.", 6},
	{"", "callum.murray@tessellateinsurance.co.uk", "Callum Murray", "Tessellate Insurance", "51-200",
		"Customer identity for our broker portal: ~40k policyholders, passkeys first, and an audit trail our FCA auditors will accept.", 18},
	{"", "tanvi.joshi@orbitalpayments.io", "Tanvi Joshi", "Orbital Payments", "11-50",
		"PCI-DSS scoped platform. Need RBAC plus ABAC, machine-to-machine tokens for 30 services, and your SOC 2 Type II report.", 33},
	{"", "henrik.nilsen@nordhavnenergy.dk", "Henrik Nilsen", "Nordhavn Energy", "200+",
		"NIS2 programme: MFA for 1,200 field technicians on shared tablets, and SSO for contractors from three partner companies.", 41},
}

// salesLeads submits the leads through the sales service, each on its day.
// A customer's lead carries its organization and owner.
func (h *history) salesLeads() {
	w := h.w
	for _, l := range leads {
		in := sales.Lead{Name: l.name, Email: l.email, Company: l.company, TeamSize: l.teamSize, Message: l.message, Source: "onboarding"}
		var organization, user *uuid.UUID
		at := w.Days(l.daysAgo)
		if l.slug != "" {
			o := orgBySlug(w, l.slug)
			if o == nil {
				continue
			}
			p := o.Person(l.email)
			if p == nil {
				continue
			}
			in.Name, in.Company, in.Source = p.Name(), o.Spec.Name, "billing"
			organization, user = ptr(o.ID), ptr(p.ID)
			at = h.workTime(p, at)
		}
		w.At(at, func() {
			w.Check(w.Deps.Sales.Service.Submit(w.Ctx, organization, user, in), "sales lead from "+l.email)
		})
	}
}

// orgBySlug is the seeded organization with slug, or nil.
func orgBySlug(w *world.World, slug string) *world.Org {
	for _, o := range w.Orgs {
		if o.Spec.Slug == slug {
			return o
		}
	}
	return nil
}
