package integrations

import (
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// keySpec is an API key: who made it and when, what it may do, and its life
// since. Days are before now; expires is days from now (negative: expired).
type keySpec struct {
	name     string
	scopes   []string
	by       []who
	created  float64
	used     float64 // last used, days ago; 0 never
	expires  float64 // 0 never expires
	personal bool    // acts as its creator
	revoked  float64 // 0 still live
	// revoker revokes it; its creator when unset.
	revoker []who
	print   bool // printed in the summary for testers
}

var (
	readDirectory = []string{"user.read", "group.read"}
	syncDirectory = []string{"user.read", "user.write", "group.read", "group.write"}
	manageInfra   = []string{"tenant.read", "role.read", "role.write", "group.read", "group.write",
		"connection.read", "connection.write", "policy.read", "policy.write"}
)

// keys are each organisation's API keys. Free plans stay within their two.
var keys = map[string][]keySpec{
	"qeet": {
		{name: "Terraform — qeet-infra (prod)", scopes: manageInfra, by: []who{both(team("Site Reliability"), builders), both(dept("Engineering"), builders)}, created: 320, used: 0.13},
		{name: "Qeet People — HRIS directory sync", scopes: syncDirectory, by: []who{email("aarav@qeet.in")}, created: 290, used: 0.006},
		{name: "Data warehouse export — BigQuery nightly", scopes: []string{"user.read", "group.read", "audit.read", "analytics.read"}, by: []who{email("rohan@qeet.in")}, created: 180, used: 0.62, print: true},
		{name: "Statuspage uptime probe", scopes: []string{"tenant.read"}, by: []who{both(team("Site Reliability"), builders)}, created: 210, used: 38.3, revoked: 38,
			revoker: []who{email("priya@qeet.in")}},
		{name: "Statuspage uptime probe (rotated)", scopes: []string{"tenant.read"}, by: []who{both(team("Site Reliability"), builders)}, created: 37.9, used: 0.003},
		{name: "Qeet Pay backoffice sync", scopes: []string{"tenant.read", "user.read", "billing.read"}, by: []who{email("diego@qeet.in")}, created: 140, used: 0.011, expires: 5},
		{name: "GitHub Actions — qeet-id-console preview deploys", scopes: []string{"connection.read", "connection.write"}, by: []who{email("ananya@qeet.in")}, created: 76, used: 0.03, expires: 12},
		{name: "Rohan Gupta — local CLI", scopes: []string{"user.read", "group.read", "role.read", "apikey.read"}, by: []who{email("rohan@qeet.in")}, created: 93, used: 3.4, expires: -3, personal: true},
	},
	"qeet-sandbox": {
		{name: "Playwright end-to-end suite", scopes: append(append([]string{}, syncDirectory...), "role.read"), by: []who{email("qa@qeet.in")}, created: 300, used: 0.05},
		{name: "k6 load test", scopes: []string{"user.read", "tenant.read"}, by: []who{email("qa@qeet.in")}, created: 31, used: 5.2},
	},
	"northwind": {
		{name: "Splunk Add-on for Qeet ID — audit pull", scopes: []string{"audit.read"}, by: []who{both(dept("Information Security"), builders)}, created: 320, used: 0.002},
		{name: "Okta Workflows — quarterly access review", scopes: []string{"user.read", "group.read", "role.read", "audit.read"}, by: []who{both(dept("Technology"), role(world.RoleDeveloper))}, created: 300, used: 0.4},
		{name: "Loan origination system (legacy LOS)", scopes: []string{"user.read"}, by: []who{both(team("Platform Engineering"), builders)}, created: 340, used: 61, revoked: 60},
		{name: "ServiceNow ITSM — joiner/mover/leaver", scopes: syncDirectory, by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, created: 250, used: 0.05, expires: 9},
		{name: "Terraform — Northwind IAM baseline", scopes: manageInfra, by: []who{both(team("Platform Engineering"), builders)}, created: 210, used: 6.2},
		{name: "Snowflake loader — Data & Analytics", scopes: []string{"user.read", "audit.read", "analytics.read"}, by: []who{both(team("Data & Analytics"), builders)}, created: 92, used: 2.1, expires: -2},
	},
	"meridian": {
		{name: "Epic Interconnect — provisioning bridge", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 240, used: 0.02},
		{name: "Imprivata OneSign — badge-tap sync", scopes: readDirectory, by: []who{both(dept("Security"), builders)}, created: 200, used: 0.1},
		{name: "Tableau — identity analytics", scopes: []string{"analytics.read", "audit.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 150, used: 1.2, expires: 20},
		{name: "PowerShell runbook — AD reconciliation", scopes: []string{"user.read", "user.write"}, by: []who{both(dept("Security"), builders)}, created: 100, used: 10.5, expires: -10},
	},
	"lumen": {
		{name: "Customer dashboard backend", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{both(team("Core Platform"), builders)}, created: 230, used: 0.001},
		{name: "Heroku worker (old billing sync)", scopes: []string{"user.read", "billing.read"}, by: []who{both(team("Core Platform"), builders)}, created: 220, used: 70.5, revoked: 70},
		{name: "GitHub Actions — lumen-cli release", scopes: []string{"connection.read", "connection.write"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 200, used: 0.2, expires: 27},
		{name: "Grafana — sign-up metrics", scopes: []string{"analytics.read"}, by: []who{both(team("Infrastructure"), builders)}, created: 160, used: 0.01},
		{name: "Staging seed script", scopes: syncDirectory, by: []who{both(team("Core Platform"), builders)}, created: 90, used: 7},
		{name: "Lucía García — local dev", scopes: readDirectory, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 50, used: 1.1, personal: true},
	},
	"aster": {
		{name: "Unicommerce — warehouse roster sync", scopes: []string{"user.read", "user.write", "group.write"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 160, used: 0.3},
		{name: "Freshdesk — agent directory sync", scopes: readDirectory, by: []who{email("meera.shetty@asterretail.in")}, created: 120, used: 0.8, expires: 6},
	},
	"vertex": {
		{name: "Okta set-up test (Tyler)", scopes: []string{"user.read", "connection.read", "connection.write"}, by: []who{email("tyler.morgan@vertexfreightco.us")}, created: 7, used: 2.1},
	},
	"kestrel": {
		{name: "Policy admin system — staff sync", scopes: []string{"user.read"}, by: []who{email("sanjay.deshpande@kestrelinsurance.in")}, created: 100, used: 3},
	},
	"cobalt": {
		{name: "Zapier — new-client onboarding", scopes: syncDirectory, by: []who{email("oliver.bennett@cobaltcreative.co.uk")}, created: 220, used: 46, revoked: 45},
		{name: "Webflow members sync", scopes: readDirectory, by: []who{email("poppy.clarke@cobaltcreative.co.uk")}, created: 200, used: 1.5},
	},
}

// apiKeys creates the organisation's API keys through the API key service,
// then stamps how each has been used, and revokes the ones that were.
func (d *dev) apiKeys(o *world.Org) {
	w := d.w
	for _, k := range keys[o.Spec.Slug] {
		days := d.jitter(k.created)
		at := d.when(o, days)
		by := person(o, at, k.by...)
		at = d.when(o, days, by)
		in := apikey.CreateInput{TenantID: o.ID, Name: k.name, Scopes: k.scopes, Actor: d.as(by)}
		if k.personal {
			in.UserID = &by.ID
		}
		if k.expires != 0 {
			exp := w.Days(-k.expires).Truncate(time.Minute)
			in.ExpiresAt = &exp
		}
		var key *apikey.Key
		var raw string
		w.At(at, func() {
			var err error
			key, raw, err = w.Deps.APIKey.Service.Create(w.Ctx, in)
			w.Check(err, "API key "+k.name)
		})
		if k.used > 0 {
			used := w.Days(k.used)
			if used.Before(at) {
				used = at.Add(time.Hour)
			}
			w.Exec("API key last used", `UPDATE auth.api_keys SET last_used_at = $3 WHERE id = $1 AND tenant_id = $2`, key.ID, o.ID, used)
		}
		if k.revoked > 0 {
			rt := d.when(o, k.revoked, by)
			revoker := person(o, rt, append(k.revoker, func(p *world.Person) bool { return p == by })...)
			w.At(rt, func() {
				w.Check(w.Deps.APIKey.Service.Revoke(w.Ctx, o.ID, key.ID, d.as(revoker)), "revoke "+k.name)
			})
		}
		if k.print {
			api := apiBase(w)
			w.Note("API keys and machine credentials", "%s — API key %q (%v)", o.Spec.Name, k.name, k.scopes)
			w.Note("API keys and machine credentials", "  curl -H 'Authorization: ApiKey %s' '%s/v1/users?limit=5'", raw, api)
		}
	}
	d.offboardedKey(o)
}

// offboardedKey gives an organisation's developer who left a personal key
// made while they were there, revoked by an administrator the day they went.
func (d *dev) offboardedKey(o *world.Org) {
	w := d.w
	p := leaver(o, role(world.RoleDeveloper, world.RoleAdmin))
	if p == nil || !o.Has("starter") {
		return
	}
	created := p.Joined.Add(time.Duration(10+w.Rand.IntN(20)) * 24 * time.Hour)
	created = w.WorkHours(created, o.Loc)
	if !created.Before(p.Since) {
		return
	}
	var key *apikey.Key
	w.At(created, func() {
		var err error
		key, _, err = w.Deps.APIKey.Service.Create(w.Ctx, apikey.CreateInput{TenantID: o.ID, UserID: &p.ID,
			Name: p.First + " " + p.Last + " — Postman workspace", Scopes: readDirectory, Actor: d.as(p)})
		w.Check(err, "leaver's API key")
	})
	w.Exec("API key last used", `UPDATE auth.api_keys SET last_used_at = $3 WHERE id = $1 AND tenant_id = $2`,
		key.ID, o.ID, p.Since.Add(-26*time.Hour))
	by := person(o, p.Since, role(world.RoleAdmin), role(world.RoleOwner))
	w.At(p.Since.Add(40*time.Minute), func() {
		w.Check(w.Deps.APIKey.Service.Revoke(w.Ctx, o.ID, key.ID, d.as(by)), "revoke leaver's key")
	})
}

// apiBase is the API's origin as testers reach it.
func apiBase(w *world.World) string {
	if w.Cfg.PublicBaseURL != "" {
		return w.Cfg.PublicBaseURL
	}
	return "http://localhost:" + w.Cfg.HTTPPort
}

// principalSpec is a service principal: a backend's own client credentials.
type principalSpec struct {
	name, description string
	scopes            []string
	by                []who
	created           float64
	disabled          float64 // days ago; 0 still enabled
	print             bool
}

// principals are each organisation's service principals.
var principals = map[string][]principalSpec{
	"qeet": {
		{name: "qeet-pay-reconciler (v1)", description: "Nightly settlement reconciler — replaced by qeet-pay-api", scopes: []string{"user.read"}, by: []who{email("diego@qeet.in")}, created: 300, disabled: 34},
		{name: "qeet-people-sync", description: "Qeet People pushes joiners, movers and leavers", scopes: syncDirectory, by: []who{email("aarav@qeet.in")}, created: 280},
		{name: "qeet-logs-shipper", description: "Ships the audit trail to Qeet Logs", scopes: []string{"audit.read"}, by: []who{both(team("Site Reliability"), builders)}, created: 240},
		{name: "qeet-notify-dispatcher", description: "Looks up recipients for Qeet Notify", scopes: []string{"user.read"}, by: []who{email("rohan@qeet.in")}, created: 150},
		{name: "qeet-pay-api", description: "Qeet Pay backend: resolves merchants' team members", scopes: []string{"tenant.read", "user.read"}, by: []who{email("diego@qeet.in")}, created: 35, print: true},
	},
	"northwind": {
		{name: "los-legacy-sync", description: "Old loan origination system user feed", scopes: []string{"user.read"}, by: []who{both(team("Platform Engineering"), builders)}, created: 330, disabled: 58},
		{name: "los-core-banking", description: "Loan origination system on Finacle", scopes: readDirectory, by: []who{both(team("Platform Engineering"), builders)}, created: 70},
		{name: "collections-dialer", description: "Predictive dialer — agent lookup", scopes: []string{"user.read"}, by: []who{both(dept("Technology"), builders)}, created: 180},
		{name: "risk-scoring-batch", description: "Nightly credit-risk scoring job", scopes: []string{"user.read", "analytics.read"}, by: []who{both(team("Data & Analytics"), builders)}, created: 140},
	},
	"meridian": {
		{name: "kronos-timekeeping-sync", description: "Kronos Workforce Central — retired for UKG Pro", scopes: []string{"user.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 250, disabled: 20},
		{name: "epic-interconnect", description: "Epic Interconnect provisioning service", scopes: []string{"user.read", "user.write"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 240},
		{name: "patient-portal-api", description: "MyMeridian patient portal backend", scopes: []string{"user.read"}, by: []who{both(dept("Security"), builders)}, created: 190},
		{name: "pyxis-dispense-bridge", description: "Pyxis MedStation badge and role sync", scopes: readDirectory, by: []who{both(dept("Security"), builders)}, created: 120},
	},
	"lumen": {
		{name: "lumen-api", description: "Lumen Cloud API — workspace membership", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{both(team("Core Platform"), builders)}, created: 230},
		{name: "billing-worker", description: "Stripe billing worker", scopes: []string{"user.read", "billing.read"}, by: []who{both(team("Core Platform"), builders)}, created: 150},
		{name: "ci-e2e", description: "End-to-end tests in CI", scopes: []string{"user.read", "user.write"}, by: []who{both(team("Infrastructure"), builders)}, created: 60},
	},
	"aster": {
		{name: "storefront-backend", description: "Shopify storefront staff lookups", scopes: []string{"user.read"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 150},
	},
}

// principals creates the organisation's service principals, audited as the
// console does, and disables the retired ones.
func (d *dev) principals(o *world.Org) {
	w := d.w
	for _, s := range principals[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		var p *principal.Principal
		var secret string
		w.At(at, func() {
			w.Tx("service principal "+s.name, func(tx pgx.Tx) error {
				var err error
				p, secret, err = w.Deps.Principal.Service.Create(w.Ctx, tx, principal.CreateInput{
					TenantID: o.ID, Name: s.name, Description: s.description, Scopes: s.scopes})
				if err != nil {
					return err
				}
				return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, "service_principal.created", "service_principal", p.ID,
					map[string]any{"name": p.Name, "scopes": p.Scopes}))
			})
		})
		if s.disabled > 0 {
			dt := d.when(o, s.disabled, by)
			w.At(dt, func() {
				w.Tx("disable "+s.name, func(tx pgx.Tx) error {
					_, name, err := w.Deps.Principal.Service.Disable(w.Ctx, tx, o.ID, p.ID)
					if err != nil {
						return err
					}
					return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, "service_principal.disabled", "service_principal", p.ID,
						map[string]any{"name": name}))
				})
			})
		}
		if s.print {
			w.Note("API keys and machine credentials", "%s — service principal %q: client_id %s  client_secret %s", o.Spec.Name, s.name, p.ID, secret)
			w.Note("API keys and machine credentials", "  curl -u '%s:%s' -d grant_type=client_credentials %s/v1/oauth/token", p.ID, secret, apiBase(w))
		}
	}
}
