package accounts

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
)

// monogram is an organisation's logo: its initials on a rounded square in its
// brand colours, as an SVG data URI (the hosted pages allow only https and
// data: images).
func monogram(name string, b world.Brand) string {
	var initials []rune
	for _, word := range strings.Fields(name) {
		if len(initials) == 2 {
			break
		}
		initials = append(initials, []rune(word)[0])
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">`+
		`<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient></defs>`+
		`<rect width="128" height="128" rx="28" fill="url(#g)"/>`+
		`<text x="64" y="81" text-anchor="middle" font-family="Inter, 'Segoe UI', Helvetica, Arial, sans-serif" font-size="50" font-weight="700" letter-spacing="-2" fill="#FFFFFF">%s</text></svg>`,
		b.Primary, b.Secondary, string(initials))
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

// sender is the name and addresses an organisation's email goes out with.
type sender struct{ name, from, replyTo string }

var senders = map[string]sender{
	"qeet":      {"Qeet Group", "accounts@qeet.in", "support@qeet.in"},
	"northwind": {"Northwind Capital IT", "it-noreply@northwindcapital.in", "itservicedesk@northwindcapital.in"},
	"meridian":  {"Meridian Health IT Service Desk", "noreply@meridianhealth.us", "servicedesk@meridianhealth.us"},
	"lumen":     {"Lumen Labs", "hello@lumenlabshq.dev", "support@lumenlabshq.dev"},
	"aster":     {"Aster Retail", "team@asterretail.in", "care@asterretail.in"},
	"vertex":    {"Vertex Freight IT", "it@vertexfreightco.us", ""},
	"kestrel":   {"Kestrel Insurance Brokers", "admin@kestrelinsurance.in", "operations@kestrelinsurance.in"},
}

// loginHosts are the custom hosted-login hostnames enterprise organisations
// set up. Neither resolves, so their DNS check stays pending.
var loginHosts = map[string]string{
	"northwind": "login.northwindcapital.in",
	"meridian":  "sso.meridianhealth.us",
}

// profile gives the organisation its logo when it is created and, where the
// plan includes custom branding, its colours, background and email sender a
// couple of days later.
func (s *seeder) profile(o *world.Org) {
	w := s.w
	logo := monogram(o.Spec.Name, o.Spec.Brand)
	w.At(o.Spec.Since.Add(5*time.Minute), func() {
		_, err := w.Deps.Tenant.Repo.Update(w.Ctx, o.ID, tenant.UpdateInput{LogoURL: &logo}, nil)
		w.Check(err, "logo of "+o.Spec.Slug)
	})
	o.Tenant.LogoURL = logo

	snd, ok := senders[o.Spec.Slug]
	if !ok || !o.Has("starter") {
		return
	}
	at := o.Spec.Since.Add(51 * time.Hour)
	if o.Spec.Slug == "vertex" {
		at = o.Spec.Since.Add(26 * time.Hour)
	}
	settings := map[string]any{"background_color": o.Spec.Brand.Background}
	if snd.replyTo != "" {
		settings["email_reply_to"] = snd.replyTo
	}
	body := map[string]any{
		"logo_url":           logo,
		"primary_color":      o.Spec.Brand.Primary,
		"secondary_color":    o.Spec.Brand.Secondary,
		"email_from_name":    snd.name,
		"email_from_address": snd.from,
		"settings":           settings,
	}
	actor := by(o, at, world.RoleITAdmin)
	w.At(at, func() { s.api.do(o, actor, "", "PUT", "/tenants/"+o.ID.String()+"/branding", body) })

	// The custom login hostname comes later, once SSO is live.
	if host, ok := loginHosts[o.Spec.Slug]; ok {
		body["custom_domain"] = host
		at := w.Days(float64(18 + w.Rand.IntN(20)))
		if o.Spec.Slug == "meridian" {
			at = w.Days(4.2)
		}
		actor := by(o, at, world.RoleITAdmin)
		w.At(at, func() { s.api.do(o, actor, "", "PUT", "/tenants/"+o.ID.String()+"/branding", body) })
	}
}

// domainPlan is a domain an organisation claims and how far it got.
type domainPlan struct {
	name, state   string // state: verified, pending or attention
	def, sso, jit bool
	added         float64 // days after the organisation signed up; negative: days ago
}

// domainPlans are each organisation's claimed email domains.
var domainPlans = map[string][]domainPlan{
	"qeet": {{name: "qeet.in", state: "verified", def: true, sso: true, jit: true, added: 1}},
	"northwind": {
		{name: "northwindcapital.in", state: "verified", def: true, sso: true, jit: true, added: 1},
		{name: "northwind-capital.co.in", state: "verified", sso: true, added: 3},
		{name: "nwcfinance.in", state: "attention", added: -12},
	},
	"meridian": {
		{name: "meridianhealth.us", state: "verified", def: true, sso: true, jit: true, added: 2},
		{name: "meridianhealthcare-us.org", state: "verified", sso: true, added: 9},
		{name: "mhn-clinics.us", state: "pending", added: -3},
	},
	"lumen": {
		{name: "lumenlabshq.dev", state: "verified", def: true, sso: true, jit: true, added: 1},
		{name: "lumenlabs-cloud.io", state: "attention", added: -6},
	},
	"aster": {
		{name: "asterretail.in", state: "verified", def: true, added: 2},
		{name: "asterfashionhouse.in", state: "pending", added: -1.5},
	},
	"vertex":  {{name: "vertexfreightco.us", state: "pending", added: 1}},
	"kestrel": {{name: "kestrelinsurance.in", state: "verified", def: true, added: 4}},
}

// domains claims the organisation's email domains: verified ones (a DNS check
// the seed can't make, so the verification is written as it would be),
// pending ones nobody has checked, and ones whose last check failed. Custom
// domains are a paid feature.
func (s *seeder) domains(o *world.Org) {
	w := s.w
	plans := domainPlans[o.Spec.Slug]
	if len(plans) == 0 || !o.Has("starter") {
		return
	}
	svc := w.Deps.DomainVerify.Service
	for _, d := range plans {
		at := o.Spec.Since.Add(time.Duration(d.added*24) * time.Hour)
		if d.added < 0 {
			at = w.Days(-d.added)
		}
		at = clamp(w, w.WorkHours(after(at, o.Spec.Since), o.Loc))
		actor := by(o, at)
		var dom *domainverify.Domain
		w.At(at, func() {
			var err error
			dom, err = svc.Add(w.Ctx, o.ID, d.name, actor.Actor())
			w.Check(err, "add domain "+d.name)
		})
		switch d.state {
		case "verified":
			checked := at.Add(time.Duration(20+w.Rand.IntN(90)) * time.Minute)
			w.Exec("verify "+d.name, `UPDATE tenant.domains SET verified_at = $3, last_checked_at = $3, last_error = NULL
				WHERE id = $1 AND tenant_id = $2`, dom.ID, o.ID, checked)
			e := actor.Actor().Event(o.ID, "domain.verified", "domain", dom.ID, map[string]any{"domain": d.name})
			w.Audit(checked, e)
			if d.def || d.sso || d.jit {
				w.At(checked.Add(4*time.Minute), func() {
					_, err := svc.UpdateSettings(w.Ctx, dom.ID, o.ID, &d.sso, &d.jit, &d.def, actor.Actor())
					w.Check(err, "domain settings "+d.name)
				})
			}
		case "attention":
			// Checked when added and again since; the TXT record never appeared.
			last := clamp(w, w.Days(0.4+w.Rand.Float64()*2))
			w.Exec("check "+d.name, `UPDATE tenant.domains SET last_checked_at = $3, last_error = 'DNS TXT record not found'
				WHERE id = $1 AND tenant_id = $2`, dom.ID, o.ID, last)
			s.tell(o, event{at: at.Add(10 * time.Minute), kind: "warning", title: "Domain verification failed",
				detail: fmt.Sprintf("We couldn't find the TXT record at _qeet-verification.%s. Publish the record, then check again.", d.name),
				href:   "/settings/organization/domains"})
		}
	}
}
