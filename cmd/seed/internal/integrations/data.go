package integrations

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
)

// who matches a person.
type who = func(*world.Person) bool

var (
	email = world.Email
	dept  = world.InDept
	team  = world.InTeam
	role  = world.HasRole
	// builders may manage API keys, webhooks and secrets; guardians policies.
	builders  = role(world.RoleOwner, world.RoleAdmin, world.RoleDeveloper)
	guardians = role(world.RoleOwner, world.RoleAdmin, world.RoleSecurity, world.RoleITAdmin)
)

// title matches people whose title contains part.
func title(part string) who {
	return func(p *world.Person) bool { return strings.Contains(p.Title, part) }
}

// both matches a person matching a and b.
func both(a, b who) who { return func(p *world.Person) bool { return a(p) && b(p) } }

// keySpec is an API key: who made it, what it may do, and what became of it.
// expires is days from now; 0 never expires.
type keySpec struct {
	name                     string
	scopes                   []string
	by, revoker              []who
	expires                  float64
	personal, revoked, print bool
}

// principalSpec is a service principal: a backend's own client credentials.
type principalSpec struct {
	name, description string
	scopes            []string
	by                []who
	disabled, print   bool
}

// agentSpec is an AI agent: the person accountable for it, who registered
// it, and whether it was suspended or decommissioned since.
type agentSpec struct {
	name        string
	scopes      []string
	ttl         int // token lifetime, seconds
	sponsor, by []who
	end         string
}

// credentialSpec is a run of verifiable credentials of one type, issued to up
// to max people matching to, ttl days long; revoke revokes one and reissues it.
type credentialSpec struct {
	typ    string
	to     who
	max    int
	ttl    float64
	claims func(p *world.Person) map[string]any
	revoke bool
}

// secretSpec is a vault secret: its name, the integration it belongs to, a
// value of the vendor's shape, how often it was rotated and whether someone
// revealed it.
type secretSpec struct {
	name, scope string
	value       func(w *world.World) string
	by          []who
	rotations   int
	revealed    bool
	rotateEvery int32 // rotation interval in days; 0 none
}

// vaultProvider is a third-party OAuth provider registered with the token vault.
type vaultProvider struct{ name, clientID, authorize, tokenPath, scopes string }

// hookSpec is a post-login hook and the change made to it since. Every
// enabled one fails open, so an unreachable seeded host never refuses a
// tester; the fail-closed ones are switched off.
type hookSpec struct {
	url      string
	failOpen bool
	by       []who
	change   *hookChange
}

type hookChange struct{ enabled, failOpen bool }

// sinkSpec is a log stream to a SIEM, streaming or switched off.
type sinkSpec struct {
	typ, endpoint string
	token         func(w *world.World) string
	by            []who
	disabled      bool
}

// subSpec is a webhook subscription: its consumer, the events it takes, and
// whether it is active or disabled by an administrator.
type subSpec struct {
	url     string
	events  []string
	by      []who
	state   string
	rotated bool
}

// abacSpec is an ABAC policy as first written, and the edits made to it
// since: each edit is a version on the console's history.
type abacSpec struct {
	name, description, effect, resource, action, condition string
	priority                                               int
	enabled                                                bool
	by                                                     []who
	edits                                                  []abacEdit
}

type abacEdit struct{ change func(*abac.UpdateInput) }

// limit is one rate-limit override: requests a second and burst.
type limit struct {
	key      string
	rate     float64
	capacity int
}

// limitChange is one save of the rate-limit form.
type limitChange struct {
	by     []who
	limits []limit
}

// tuple is a relationship: object, relation, subject. A subject "team:<name>"
// is everyone active in that team, and "user:<email>" that person.
type tuple [3]string

// relations are the ReBAC graphs of the organizations that draw one.
var relations = map[string][]tuple{
	"qeet": {
		{"group:engineering", "member", "team:Qeet ID"}, {"group:engineering", "member", "team:Qeet Pay"},
		{"group:engineering", "member", "team:Site Reliability"}, {"group:product-management", "member", "team:Product Management"},
		{"folder:engineering-handbook", "owner", "user:aarav@qeet.in"}, {"folder:engineering-handbook", "viewer", "group:engineering#member"},
		{"document:readme", "parent", "folder:engineering-handbook"}, {"document:readme", "owner", "user:rohan@qeet.in"},
		{"document:readme", "viewer", "folder:engineering-handbook#viewer"}, {"document:readme", "viewer", "group:product-management#member"},
		{"document:readme", "viewer", "user:grace@qeet.in"},
		{"folder:finance", "owner", "user:vikram@qeet.in"}, {"document:fy27-budget", "parent", "folder:finance"},
		{"document:fy27-budget", "viewer", "folder:finance#viewer"}, {"document:fy27-budget", "editor", "user:vikram@qeet.in"},
	},
	"lumen": {
		{"group:engineering", "member", "team:Core Platform"}, {"group:cli-and-sdks", "member", "team:CLI & SDKs"},
		{"workspace:lumen-cloud", "admin", "user:jonas.becker@lumenlabshq.dev"}, {"workspace:lumen-cloud", "member", "group:engineering#member"},
		{"repository:lumen-cli", "maintainer", "group:cli-and-sdks#member"}, {"repository:lumen-cli", "reader", "workspace:lumen-cloud#member"},
		{"document:readme", "parent", "repository:lumen-cli"}, {"document:readme", "owner", "user:lucia.garcia@lumenlabshq.dev"},
		{"document:readme", "viewer", "repository:lumen-cli#reader"},
	},
	"northwind": {
		{"group:credit-underwriting", "member", "team:Credit Underwriting"}, {"folder:credit-policies", "viewer", "group:credit-underwriting#member"},
		{"document:readme", "parent", "folder:credit-policies"}, {"document:readme", "viewer", "folder:credit-policies#viewer"},
		{"document:sanction-matrix-fy27", "parent", "folder:credit-policies"}, {"document:sanction-matrix-fy27", "viewer", "group:credit-underwriting#member"},
	},
	"meridian": {
		{"group:information-technology", "member", "team:Service Desk"}, {"document:readme", "owner", "user:marcus.brooks@meridianhealth.us"},
		{"document:readme", "viewer", "group:information-technology#member"},
		{"document:downtime-procedures", "editor", "user:jennifer.walsh@meridianhealth.us"},
		{"document:downtime-procedures", "viewer", "group:information-technology#member"},
	},
}

// keys are each organization's API keys. Free plans stay within their two.
var keys = map[string][]keySpec{
	"qeet": {
		{name: "Terraform — qeet-infra (prod)", scopes: manageInfra, by: []who{both(team("Site Reliability"), builders), both(dept("Engineering"), builders)}},
		{name: "Qeet People — HRIS directory sync", scopes: syncDirectory, by: []who{email("aarav@qeet.in")}},
		{name: "Data warehouse export — BigQuery nightly", scopes: []string{"user.read", "group.read", "audit.read", "analytics.read"}, by: []who{email("rohan@qeet.in")}, print: true},
		{name: "Statuspage uptime probe", scopes: []string{"organization.read"}, by: []who{both(team("Site Reliability"), builders)}, revoked: true,
			revoker: []who{email("priya@qeet.in")}},
		{name: "Statuspage uptime probe (rotated)", scopes: []string{"organization.read"}, by: []who{both(team("Site Reliability"), builders)}},
		{name: "Qeet Pay backoffice sync", scopes: []string{"organization.read", "user.read", "billing.read"}, by: []who{email("diego@qeet.in")}, expires: 5},
		{name: "GitHub Actions — qeet-id-console preview deploys", scopes: []string{"connection.read", "connection.write"}, by: []who{email("ananya@qeet.in")}, expires: 12},
		{name: "Rohan Gupta — local CLI", scopes: []string{"user.read", "group.read", "role.read", "apikey.read"}, by: []who{email("rohan@qeet.in")}, expires: 2, personal: true},
	},
	"qeet-sandbox": {
		{name: "Playwright end-to-end suite", scopes: append(append([]string{}, syncDirectory...), "role.read"), by: []who{email("qa@qeet.in")}},
		{name: "k6 load test", scopes: []string{"user.read", "organization.read"}, by: []who{email("qa@qeet.in")}},
	},
	"northwind": {
		{name: "Splunk Add-on for Qeet ID — audit pull", scopes: []string{"audit.read"}, by: []who{both(dept("Information Security"), builders)}},
		{name: "Okta Workflows — quarterly access review", scopes: []string{"user.read", "group.read", "role.read", "audit.read"}, by: []who{both(dept("Technology"), role(world.RoleDeveloper))}},
		{name: "Loan origination system (legacy LOS)", scopes: []string{"user.read"}, by: []who{both(team("Platform Engineering"), builders)}, revoked: true},
		{name: "ServiceNow ITSM — joiner/mover/leaver", scopes: syncDirectory, by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, expires: 9},
		{name: "Terraform — Northwind IAM baseline", scopes: manageInfra, by: []who{both(team("Platform Engineering"), builders)}},
		{name: "Snowflake loader — Data & Analytics", scopes: []string{"user.read", "audit.read", "analytics.read"}, by: []who{both(team("Data & Analytics"), builders)}, expires: 2},
	},
	"meridian": {
		{name: "Epic Interconnect — provisioning bridge", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}},
		{name: "Imprivata OneSign — badge-tap sync", scopes: readDirectory, by: []who{both(dept("Security"), builders)}},
		{name: "Tableau — identity analytics", scopes: []string{"analytics.read", "audit.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, expires: 20},
		{name: "PowerShell runbook — AD reconciliation", scopes: []string{"user.read", "user.write"}, by: []who{both(dept("Security"), builders)}, expires: 2},
	},
	"lumen": {
		{name: "Customer dashboard backend", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{both(team("Core Platform"), builders)}},
		{name: "Heroku worker (old billing sync)", scopes: []string{"user.read", "billing.read"}, by: []who{both(team("Core Platform"), builders)}, revoked: true},
		{name: "GitHub Actions — lumen-cli release", scopes: []string{"connection.read", "connection.write"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, expires: 27},
		{name: "Grafana — sign-up metrics", scopes: []string{"analytics.read"}, by: []who{both(team("Infrastructure"), builders)}},
		{name: "Staging seed script", scopes: syncDirectory, by: []who{both(team("Core Platform"), builders)}},
		{name: "Lucía García — local dev", scopes: readDirectory, by: []who{email("lucia.garcia@lumenlabshq.dev")}, personal: true},
	},
	"aster": {
		{name: "Unicommerce — warehouse roster sync", scopes: []string{"user.read", "user.write", "group.write"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}},
		{name: "Freshdesk — agent directory sync", scopes: readDirectory, by: []who{email("meera.shetty@asterretail.in")}, expires: 6},
	},
	"vertex": {
		{name: "Okta set-up test (Tyler)", scopes: []string{"user.read", "connection.read", "connection.write"}, by: []who{email("tyler.morgan@vertexfreightco.us")}},
	},
	"kestrel": {
		{name: "Policy admin system — staff sync", scopes: []string{"user.read"}, by: []who{email("sanjay.deshpande@kestrelinsurance.in")}},
	},
	"cobalt": {
		{name: "Zapier — new-client onboarding", scopes: syncDirectory, by: []who{email("oliver.bennett@cobaltcreative.co.uk")}, revoked: true},
		{name: "Webflow members sync", scopes: readDirectory, by: []who{email("poppy.clarke@cobaltcreative.co.uk")}},
	},
}

// principalSpecs are each organization's service principals.
var principalSpecs = map[string][]principalSpec{
	"qeet": {
		{name: "qeet-pay-reconciler (v1)", description: "Nightly settlement reconciler — replaced by qeet-pay-api", scopes: []string{"user.read"}, by: []who{email("diego@qeet.in")}, disabled: true},
		{name: "qeet-people-sync", description: "Qeet People pushes joiners, movers and leavers", scopes: syncDirectory, by: []who{email("aarav@qeet.in")}},
		{name: "qeet-logs-shipper", description: "Ships the audit trail to Qeet Logs", scopes: []string{"audit.read"}, by: []who{both(team("Site Reliability"), builders)}},
		{name: "qeet-notify-dispatcher", description: "Looks up recipients for Qeet Notify", scopes: []string{"user.read"}, by: []who{email("rohan@qeet.in")}},
		{name: "qeet-pay-api", description: "Qeet Pay backend: resolves merchants' team members", scopes: []string{"organization.read", "user.read"}, by: []who{email("diego@qeet.in")}, print: true},
	},
	"northwind": {
		{name: "los-legacy-sync", description: "Old loan origination system user feed", scopes: []string{"user.read"}, by: []who{both(team("Platform Engineering"), builders)}, disabled: true},
		{name: "los-core-banking", description: "Loan origination system on Finacle", scopes: readDirectory, by: []who{both(team("Platform Engineering"), builders)}},
		{name: "collections-dialer", description: "Predictive dialer — agent lookup", scopes: []string{"user.read"}, by: []who{both(dept("Technology"), builders)}},
		{name: "risk-scoring-batch", description: "Nightly credit-risk scoring job", scopes: []string{"user.read", "analytics.read"}, by: []who{both(team("Data & Analytics"), builders)}},
	},
	"meridian": {
		{name: "kronos-timekeeping-sync", description: "Kronos Workforce Central — retired for UKG Pro", scopes: []string{"user.read"}, by: []who{email("jennifer.walsh@meridianhealth.us")}, disabled: true},
		{name: "epic-interconnect", description: "Epic Interconnect provisioning service", scopes: []string{"user.read", "user.write"}, by: []who{email("jennifer.walsh@meridianhealth.us")}},
		{name: "patient-portal-api", description: "MyMeridian patient portal backend", scopes: []string{"user.read"}, by: []who{both(dept("Security"), builders)}},
		{name: "pyxis-dispense-bridge", description: "Pyxis MedStation badge and role sync", scopes: readDirectory, by: []who{both(dept("Security"), builders)}},
	},
	"lumen": {
		{name: "lumen-api", description: "Lumen Cloud API — workspace membership", scopes: []string{"user.read", "user.write", "group.read"}, by: []who{both(team("Core Platform"), builders)}},
		{name: "billing-worker", description: "Stripe billing worker", scopes: []string{"user.read", "billing.read"}, by: []who{both(team("Core Platform"), builders)}},
		{name: "ci-e2e", description: "End-to-end tests in CI", scopes: []string{"user.read", "user.write"}, by: []who{both(team("Infrastructure"), builders)}},
	},
	"aster": {
		{name: "storefront-backend", description: "Shopify storefront staff lookups", scopes: []string{"user.read"}, by: []who{email("lucia.garcia@lumenlabshq.dev")}},
	},
}

// agentSpecs are each organization's AI agents.
var agentSpecs = map[string][]agentSpec{
	"qeet": {
		{name: "Onboarding Buddy (pilot)", scopes: []string{"user.read", "vault:slack"}, ttl: 600,
			sponsor: []who{title("People Partner"), email("vikram@qeet.in")}, by: []who{email("rohan@qeet.in")}, end: "decommissioned"},
		{name: "Support Copilot", scopes: []string{"user.read", "vault:zendesk", "vault:slack"}, ttl: 900,
			sponsor: []who{email("sneha@qeet.in")}, by: []who{email("rohan@qeet.in")}},
		{name: "Sales Research Agent", scopes: []string{"vault:hubspot", "vault:google-drive"}, ttl: 1800,
			sponsor: []who{title("VP Sales"), dept("Sales")}, by: []who{email("rohan@qeet.in")}, end: "suspended"},
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:slack"}, ttl: 600,
			sponsor: []who{email("grace@qeet.in")}, by: []who{email("aarav@qeet.in")}},
		{name: "Invoice Triage Agent", scopes: []string{"billing.read", "vault:google-drive"}, ttl: 600,
			sponsor: []who{email("vikram@qeet.in")}, by: []who{email("diego@qeet.in")}},
	},
	"northwind": {
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:servicenow"}, ttl: 600,
			sponsor: []who{email("kavya.menon@northwindcapital.in")}, by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}},
		{name: "Loan Document Triage Agent", scopes: []string{"user.read", "vault:salesforce"}, ttl: 900,
			sponsor: []who{title("Chief Risk Officer"), dept("Credit & Risk")}, by: []who{both(team("Platform Engineering"), builders)}},
		{name: "Collections Reminder Agent", scopes: []string{"vault:salesforce"}, ttl: 600,
			sponsor: []who{team("Collections")}, by: []who{both(team("Platform Engineering"), builders)}, end: "suspended"},
	},
	"meridian": {
		{name: "Clinical Scheduling Bot", scopes: []string{"user.read"}, ttl: 600,
			sponsor: []who{title("Chief Nursing Officer"), dept("Clinical Operations")}, by: []who{email("jennifer.walsh@meridianhealth.us")}, end: "decommissioned"},
		{name: "IT Helpdesk Agent", scopes: []string{"user.read", "group.read", "vault:servicenow"}, ttl: 600,
			sponsor: []who{email("marcus.brooks@meridianhealth.us")}, by: []who{email("jennifer.walsh@meridianhealth.us")}},
		{name: "Prior Authorization Assistant", scopes: []string{"user.read"}, ttl: 900,
			sponsor: []who{title("Director of Revenue Cycle"), dept("Revenue Cycle")}, by: []who{both(dept("Security"), builders)}},
	},
	"lumen": {
		{name: "Docs Q&A Agent", scopes: []string{"vault:github", "vault:linear"}, ttl: 900,
			sponsor: []who{title("Head of DevRel"), dept("Developer Relations")}, by: []who{email("lucia.garcia@lumenlabshq.dev")}},
		{name: "Support Copilot", scopes: []string{"user.read", "vault:slack", "vault:linear"}, ttl: 900,
			sponsor: []who{email("jonas.becker@lumenlabshq.dev")}, by: []who{both(team("Core Platform"), builders)}},
		{name: "Changelog Writer", scopes: []string{"vault:github", "vault:slack"}, ttl: 600,
			sponsor: []who{email("lucia.garcia@lumenlabshq.dev")}, by: []who{email("lucia.garcia@lumenlabshq.dev")}, end: "suspended"},
	},
	"aster": {
		{name: "Order Status Agent", scopes: []string{"user.read"}, ttl: 600,
			sponsor: []who{title("Customer Care Manager"), dept("Customer Care")}, by: []who{email("meera.shetty@asterretail.in")}},
	},
}

// credentialSpecs are each organization's verifiable credentials.
var credentialSpecs = map[string][]credentialSpec{
	"qeet": {
		{typ: "EmployeeCredential", to: func(*world.Person) bool { return true }, max: 9, ttl: 365, claims: employee("Qeet Group"), revoke: true},
		{typ: "BuildingAccessCredential", to: dept("Sales"), max: 2, ttl: 120, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "site": "Qeet Group, HSR Layout, Bengaluru", "access_level": "office-hours", "badge": "QB-" + p.EmployeeID[4:]}
		}},
	},
	"northwind": {
		{typ: "EmployeeCredential", to: dept("Credit & Risk"), max: 5, ttl: 365, claims: employee("Northwind Capital"), revoke: true},
		{typ: "AMLTrainingCredential", to: dept("Loan Operations"), max: 4, ttl: 365, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "course": "PMLA & KYC refresher", "score": 80 + len(p.Last)%20}
		}},
	},
	"meridian": {
		{typ: "NursingLicenseCredential", to: title("Nurse"), max: 5, ttl: 700, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "license_number": "RN" + p.EmployeeID[4:] + "7", "jurisdiction": "Massachusetts Board of Registration in Nursing", "license_type": "Registered Nurse"}
		}, revoke: true},
		{typ: "HIPAATrainingCredential", to: dept("Revenue Cycle"), max: 3, ttl: 251, claims: func(p *world.Person) map[string]any {
			return map[string]any{"name": p.Name(), "course": "HIPAA Privacy & Security 2026", "completed": true}
		}},
	},
	"lumen": {
		{typ: "EmployeeCredential", to: dept("Developer Relations"), max: 3, ttl: 365, claims: employee("Lumen Labs GmbH")},
	},
}

// employee is the claims of an employment credential from employer.
func employee(employer string) func(p *world.Person) map[string]any {
	return func(p *world.Person) map[string]any {
		return map[string]any{"name": p.Name(), "email": p.Email, "employer": employer, "title": p.Title,
			"department": p.Department, "employee_id": p.EmployeeID}
	}
}

// prefixed is a vendor key: prefix, then n random characters.
func prefixed(prefix string, n int) func(w *world.World) string {
	return func(w *world.World) string { return prefix + w.Token(world.Alnum, n) }
}

// hexed is n random hex digits.
func hexed(n int) func(w *world.World) string {
	return func(w *world.World) string { return w.Token(world.Hex, n) }
}

// pem is a PEM private key, base64-encoded the way CI variables carry one.
func pem(w *world.World) string {
	line := func() string { return w.Token(world.Alnum+"+/", 64) }
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + line() + "\n" + line() + "\n-----END RSA PRIVATE KEY-----\n"
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// secretSpecs are each organization's vault secrets.
var secretSpecs = map[string][]secretSpec{
	"qeet": {
		{name: "RAZORPAY_KEY_SECRET", scope: "payments", value: prefixed("", 24), by: []who{email("diego@qeet.in")}, rotations: 1, rotateEvery: 90},
		{name: "STRIPE_SECRET_KEY", scope: "payments", value: prefixed("sk_live_51P", 96), by: []who{email("diego@qeet.in")}, rotations: 2, revealed: true, rotateEvery: 90},
		{name: "MSG91_AUTH_KEY", scope: "sms", value: prefixed("", 26), by: []who{email("rohan@qeet.in")}},
		{name: "SLACK_BOT_TOKEN", scope: "alerts", value: prefixed("xoxb-5512398172-", 40), by: []who{both(team("Site Reliability"), builders)}},
		{name: "PAGERDUTY_ROUTING_KEY", scope: "on-call", value: hexed(32), by: []who{both(team("Site Reliability"), builders)}},
		{name: "GITHUB_APP_PRIVATE_KEY_B64", scope: "ci", value: pem, by: []who{email("rohan@qeet.in")}, rotations: 1},
		{name: "ANTHROPIC_API_KEY", scope: "qeet-ai", value: prefixed("sk-ant-api03-", 80), by: []who{email("rohan@qeet.in")}, revealed: true},
	},
	"northwind": {
		{name: "CIBIL_API_KEY", scope: "credit-bureau", value: prefixed("", 32), by: []who{both(team("Platform Engineering"), builders)}, rotations: 1, rotateEvery: 180},
		{name: "EXPERIAN_CLIENT_SECRET", scope: "credit-bureau", value: prefixed("", 40), by: []who{both(team("Platform Engineering"), builders)}},
		{name: "NSDL_PAN_VERIFY_TOKEN", scope: "kyc", value: hexed(40), by: []who{both(team("Platform Engineering"), builders)}},
		{name: "SPLUNK_HEC_TOKEN", scope: "siem", value: func(w *world.World) string {
			return uuid.NewSHA1(uuid.NameSpaceURL, []byte(w.Token(world.Alnum, 12))).String()
		}, by: []who{both(dept("Information Security"), builders)}, rotations: 1, rotateEvery: 90},
		{name: "OKTA_API_TOKEN", scope: "identity", value: prefixed("00", 40), by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, revealed: true},
		{name: "KARIX_SMS_API_KEY", scope: "sms", value: prefixed("", 28), by: []who{both(team("Platform Engineering"), builders)}},
	},
	"meridian": {
		{name: "EPIC_INTERCONNECT_CLIENT_SECRET", scope: "ehr", value: prefixed("", 48), by: []who{email("jennifer.walsh@meridianhealth.us")}, rotations: 1},
		{name: "SURESCRIPTS_API_KEY", scope: "e-prescribing", value: prefixed("", 32), by: []who{email("jennifer.walsh@meridianhealth.us")}},
		{name: "DATADOG_API_KEY", scope: "observability", value: hexed(32), by: []who{both(dept("Security"), builders)}, rotations: 1},
		{name: "TWILIO_AUTH_TOKEN", scope: "patient-sms", value: hexed(32), by: []who{both(dept("Security"), builders)}},
		{name: "SERVICENOW_INTEGRATION_PASSWORD", scope: "itsm", value: prefixed("", 20), by: []who{email("jennifer.walsh@meridianhealth.us")}, revealed: true},
	},
	"lumen": {
		{name: "STRIPE_SECRET_KEY", scope: "billing", value: prefixed("sk_live_51O", 96), by: []who{both(team("Core Platform"), builders)}, rotations: 1},
		{name: "POSTMARK_SERVER_TOKEN", scope: "email", value: func(w *world.World) string {
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte(w.Token(world.Alnum, 12))).String()
		}, by: []who{both(team("Core Platform"), builders)}},
		{name: "GITHUB_APP_PRIVATE_KEY_B64", scope: "github-app", value: pem, by: []who{email("lucia.garcia@lumenlabshq.dev")}},
		{name: "SENTRY_AUTH_TOKEN", scope: "observability", value: prefixed("sntrys_", 64), by: []who{both(team("Infrastructure"), builders)}},
		{name: "CLOUDFLARE_API_TOKEN", scope: "infra", value: prefixed("", 40), by: []who{both(team("Infrastructure"), builders)}, rotations: 1},
	},
	"aster": {
		{name: "SHOPIFY_ADMIN_API_TOKEN", scope: "storefront", value: prefixed("shpat_", 32), by: []who{email("meera.shetty@asterretail.in")}},
		{name: "RAZORPAY_KEY_SECRET", scope: "payments", value: prefixed("", 24), by: []who{email("meera.shetty@asterretail.in")}},
		{name: "DELHIVERY_API_TOKEN", scope: "shipping", value: hexed(40), by: []who{email("lucia.garcia@lumenlabshq.dev")}},
		{name: "GUPSHUP_WHATSAPP_API_KEY", scope: "messaging", value: prefixed("sk_", 32), by: []who{email("meera.shetty@asterretail.in")}},
	},
	"vertex": {
		{name: "OKTA_API_TOKEN", scope: "identity", value: prefixed("00", 40), by: []who{email("tyler.morgan@vertexfreightco.us")}},
	},
}

// vaultProviders are each organization's token-vault providers. Browsers are
// sent to the vendor's real authorize page; the server exchanges codes
// through the organization's own egress gateway, a host that doesn't resolve.
var vaultProviders = map[string][]vaultProvider{
	"qeet": {
		{"slack", "5512398172.7829104456213", "https://slack.com/oauth/v2/authorize", "/slack/api/oauth.v2.access", "chat:write channels:read users:read"},
		{"google-drive", "1048576302214-k3q9v2n8m1c7x5z4b6a0d2f8h1j3l5p7.apps.googleusercontent.com", "https://accounts.google.com/o/oauth2/v2/auth",
			"/google/token", "https://www.googleapis.com/auth/drive.readonly"},
		{"hubspot", "6b1f0c2e-58d4-4a8e-9f3b-2c7d1e9a4b60", "https://app.hubspot.com/oauth/authorize", "/hubspot/oauth/v1/token",
			"crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read"},
		{"zendesk", "qeet_id_token_vault", "https://qeetgroup.zendesk.com/oauth/authorizations/new", "/zendesk/oauth/tokens", "tickets:read users:read"},
	},
	"northwind": {
		{"salesforce", "3MVG9n_HvETGhr3Bq7xZ1pL0kTqWd8yR5uFs2cA6mJbNe4XoPiK", "https://login.salesforce.com/services/oauth2/authorize",
			"/salesforce/services/oauth2/token", "api refresh_token"},
		{"servicenow", "a6f0c41d3e9b4b7c8d2e5f1a0b9c7d3e", "https://northwindcapital.service-now.com/oauth_auth.do", "/servicenow/oauth_token.do", "useraccount"},
	},
	"meridian": {
		{"servicenow", "0d7e2c9b5a1f4e6d8c3b7a2f9e1d5c4b", "https://meridianhealth.service-now.com/oauth_auth.do", "/servicenow/oauth_token.do", "useraccount"},
	},
	"lumen": {
		{"github", "Iv23liQ8xZp4kT7wR2mN", "https://github.com/login/oauth/authorize", "/github/login/oauth/access_token", "repo read:org"},
		{"slack", "4408817265.7716209933480", "https://slack.com/oauth/v2/authorize", "/slack/api/oauth.v2.access", "chat:write channels:history users:read"},
		{"linear", "c2f9a1e0b7d84e3f9a6c5b2d1e0f7a8b", "https://linear.app/oauth/authorize", "/linear/oauth/token", "read write"},
	},
}

// hookSpecs are each organization's post-login hooks, on hosts that do not
// resolve.
var hookSpecs = map[string][]hookSpec{
	"qeet": {
		{url: "https://risk.qeet.in/v1/login-decision", failOpen: false, by: []who{email("rohan@qeet.in")},
			change: &hookChange{enabled: false, failOpen: false}},
		{url: "https://hooks.qeet.in/qeet-id/post-login/claims", failOpen: true, by: []who{email("rohan@qeet.in")},
			change: &hookChange{enabled: false, failOpen: true}},
	},
	"northwind": {
		{url: "https://fraud-gateway.northwindcapital.in/v2/login-screen", failOpen: false, by: []who{both(team("Platform Engineering"), builders)},
			change: &hookChange{enabled: false, failOpen: false}},
		{url: "https://risk-engine.northwindcapital.in/qeet/post-login", failOpen: false, by: []who{both(team("Platform Engineering"), builders)},
			change: &hookChange{enabled: true, failOpen: true}},
	},
	"meridian": {
		{url: "https://iam-hooks.meridianhealth.us/qeet/post-login", failOpen: true, by: []who{email("jennifer.walsh@meridianhealth.us")}},
	},
	"lumen": {
		{url: "https://api.lumenlabshq.dev/internal/hooks/post-login", failOpen: true, by: []who{both(team("Core Platform"), builders)},
			change: &hookChange{enabled: false, failOpen: true}},
	},
}

// sinkSpecs are each organization's log streams. No endpoint is a vendor's
// own intake host: each goes through a relay on the organization's domain,
// which does not resolve.
var sinkSpecs = map[string][]sinkSpec{
	"qeet": {
		{typ: "http", endpoint: "https://ingest.logs.qeet.in/v1/http/qeet-id", token: prefixed("qlog_", 40),
			by: []who{both(team("Site Reliability"), builders)}},
	},
	"northwind": {
		{typ: "http", endpoint: "https://arcsight-sc.northwindcapital.in/receiver/v1/events", token: hexed(32),
			by: []who{both(dept("Information Security"), builders)}, disabled: true},
		{typ: "splunk_hec", endpoint: "https://splunk-hec.northwindcapital.in:8088/services/collector/event",
			token: func(w *world.World) string {
				return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(w.Token(world.Alnum, 12))).String()
			},
			by: []who{both(dept("Information Security"), builders)}},
	},
	"meridian": {
		{typ: "datadog", endpoint: "https://dd-relay.meridianhealth.us/api/v2/logs", token: hexed(32),
			by: []who{both(dept("Security"), builders)}},
	},
}

// subSpecs are each organization's webhook subscriptions, on its own hosts,
// none of which resolve.
var subSpecs = map[string][]subSpec{
	"qeet": {
		{url: "https://hooks.qeet.in/people/qeet-id-events", events: append(append([]string{}, userEvents...), groupEvents...),
			by: []who{email("aarav@qeet.in")}, state: "active", rotated: true},
		{url: "https://notify.qeet.in/v1/sources/qeet-id/webhooks", events: []string{"user.created", "user.password_set", "auth.password_changed", "session.revoked", "agent.suspended"},
			by: []who{email("rohan@qeet.in")}, state: "active"},
		{url: "https://alerts.qeet.in/slack/identity-alerts", events: alertEvents,
			by: []who{both(team("Site Reliability"), builders)}, state: "active"},
		{url: "https://warehouse.qeet.in/ingest/qeet-id/webhooks", events: []string{"user.created", "user.deleted", "session.revoked", "auth.password_changed", "group.member_added"},
			by: []who{email("rohan@qeet.in")}, state: "disabled"},
		{url: "https://staging-api.qeet.in/notify/v1/webhooks/qeet-id", events: []string{"user.created", "user.password_set", "auth.password_changed", "session.revoked"},
			by: []who{email("rohan@qeet.in")}, state: "active"},
	},
	"northwind": {
		{url: "https://siem-relay.northwindcapital.in/qeet-id/events", events: []string{"user.suspended", "user.deleted", "user.password_set", "session.revoked",
			"oidc.client_locked_out", "agent.suspended", "agent.kill_switch", "abac_policy.updated", "abac_policy.deleted", "rate_limits.updated"},
			by: []who{both(dept("Information Security"), builders)}, state: "active"},
		{url: "https://itsm-bridge.northwindcapital.in/servicenow/qeet-id", events: append(append([]string{}, userEvents...), "group.member_added", "group.member_removed"),
			by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, state: "active"},
		{url: "https://los-hooks.northwindcapital.in/legacy/qeet", events: []string{"user.created", "user.deleted"},
			by: []who{both(team("Platform Engineering"), builders)}, state: "disabled"},
	},
	"meridian": {
		{url: "https://epic-bridge.meridianhealth.us/qeet-id/webhooks", events: userEvents,
			by: []who{email("jennifer.walsh@meridianhealth.us")}, state: "active"},
		{url: "https://teams-relay.meridianhealth.us/identity-alerts", events: alertEvents,
			by: []who{both(dept("Security"), builders)}, state: "active"},
		{url: "https://dw-ingest.meridianhealth.us/qeet-id/events", events: append(append([]string{}, userEvents...), "group.member_added", "group.member_removed", "session.revoked"),
			by: []who{both(dept("Security"), builders)}, state: "active"},
	},
	"lumen": {
		{url: "https://api.lumenlabshq.dev/internal/webhooks/qeet-id", events: []string{"user.created", "user.deleted", "session.revoked", "token.claims_change", "group.member_added", "group.member_removed"},
			by: []who{both(team("Core Platform"), builders)}, state: "active", rotated: true},
		{url: "https://hooks.lumenlabshq.dev/slack/identity-alerts", events: []string{"agent.suspended", "agent.kill_switch", "abac_policy.updated",
			"auth_hook.updated", "credential.revoked", "oidc.client_locked_out", "rate_limits.updated"},
			by: []who{email("lucia.garcia@lumenlabshq.dev")}, state: "active"},
		{url: "https://events.lumenlabshq.dev/segment/forward", events: []string{"user.created", "user.deleted", "session.revoked"},
			by: []who{both(team("Core Platform"), builders)}, state: "disabled"},
	},
	"aster": {
		{url: "https://ops.asterretail.in/hooks/qeet-id/staff-roster", events: []string{"user.created", "user.suspended", "user.deleted", "group.member_added", "group.member_removed"},
			by: []who{email("lucia.garcia@lumenlabshq.dev")}, state: "active"},
	},
}
var (
	readDirectory = []string{"user.read", "group.read"}
	syncDirectory = []string{"user.read", "user.write", "group.read", "group.write"}
	manageInfra   = []string{"organization.read", "role.read", "role.write", "group.read", "group.write",
		"connection.read", "connection.write", "policy.read", "policy.write"}
)
var (
	userEvents  = []string{"user.created", "user.updated", "user.suspended", "user.reactivated", "user.deleted"}
	groupEvents = []string{"group.created", "group.updated", "group.deleted", "group.member_added", "group.member_removed"}
	alertEvents = []string{"user.suspended", "user.deleted", "user.password_set", "auth.password_changed", "session.revoked",
		"oidc.client_locked_out", "agent.suspended", "agent.kill_switch", "agent.decommissioned", "auth_hook.updated",
		"auth_hook.deleted", "siem.sink_updated", "siem.sink_deleted", "abac_policy.updated", "abac_policy.deleted",
		"rate_limits.updated", "credential.revoked", "organization.suspended"}
)

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

// abacSpecs are each Pro or Enterprise organization's ABAC policies.
var abacSpecs = map[string][]abacSpec{
	"qeet": {
		{name: "Block sanctioned countries", description: "Refuse every action from comprehensively sanctioned jurisdictions (OFAC/UN lists).",
			effect: "deny", resource: "*", action: "*", priority: 1000, enabled: true, by: []who{email("priya@qeet.in")},
			condition: within("CU", "IR", "KP", "SY")},
		{name: "Contractors: business hours only", description: "Contractors may work 09:00–18:00 IST.",
			effect: "deny", resource: "*", action: "*", priority: 500, enabled: true, by: []who{email("priya@qeet.in")},
			condition: contractorHours, edits: []abacEdit{
				{change: func(u *abac.UpdateInput) {
					u.Condition = json.RawMessage(contractorHoursWide)
					u.Description = "Contractors may work 08:00–20:00 IST on weekdays (extended for the payments migration)."
				}},
				{change: func(u *abac.UpdateInput) { u.Priority = 600 }},
			}},
		{name: "Finance ledgers require MFA", description: "Reading or changing ledgers needs a second factor in this session.",
			effect: "deny", resource: "ledger", action: "read", priority: 400, enabled: true, by: []who{email("priya@qeet.in")},
			condition: withoutMFA, edits: []abacEdit{{change: func(u *abac.UpdateInput) { u.Action = "*" }}}},
		{name: "Payouts approved from India only", description: "RBI: settlement approvals only from Indian networks.",
			effect: "deny", resource: "payout", action: "approve", priority: 300, enabled: true, by: []who{both(dept("Security"), guardians)},
			condition: outside("IN")},
		{name: "Engineers read production logs", description: "Engineering may read the production log streams.",
			effect: "allow", resource: "log_stream", action: "read", priority: 100, enabled: true, by: []who{email("priya@qeet.in")},
			condition: `{"attr":"subject.department","op":"eq","value":"Engineering"}`},
		{name: "Everyone reads the employee handbook", description: "The handbook is open to all staff.",
			effect: "allow", resource: "document", action: "read", priority: 10, enabled: true, by: []who{email("aarav@qeet.in")},
			condition: `{}`},
		{name: "Freeze payment config during SOC 2 window", description: "No payment configuration changes while the auditors sample.",
			effect: "deny", resource: "payment_config", action: "write", priority: 900, enabled: true, by: []who{email("priya@qeet.in")},
			condition: `{}`, edits: []abacEdit{{change: func(u *abac.UpdateInput) {
				u.Enabled = false
				u.Description = "Lifted after fieldwork closed; kept for the next audit window."
			}}}},
	},
	"northwind": {
		{name: "Loan approvals require MFA", description: "Sanction and disbursal approvals need a second factor.",
			effect: "deny", resource: "loan_application", action: "approve", priority: 800, enabled: true, by: []who{both(dept("Information Security"), guardians)},
			condition: withoutMFA},
		{name: "Credit bureau data from India only", description: "CICRA: bureau reports stay within Indian networks.",
			effect: "deny", resource: "credit_report", action: "*", priority: 700, enabled: true, by: []who{both(dept("Information Security"), guardians)},
			condition: outside("IN"), edits: []abacEdit{{change: func(u *abac.UpdateInput) {
				u.Condition = json.RawMessage(outside("IN", "AE"))
				u.Description = "CICRA: bureau reports stay within Indian networks and the Dubai representative office."
			}}}},
		{name: "Contractors: business hours only", description: "Vendor staff may work 09:00–18:00 IST.",
			effect: "deny", resource: "*", action: "*", priority: 600, enabled: true, by: []who{both(dept("Information Security"), guardians)},
			condition: contractorHours},
		{name: "Collections agents see their assigned accounts", description: "A collections officer reads only the loan accounts assigned to them.",
			effect: "allow", resource: "loan_account", action: "read", priority: 200, enabled: true, by: []who{both(dept("Information Security"), guardians)},
			condition: `{"attr":"resource.assigned_to","op":"eq","value":{"attr":"subject.id"}}`},
		{name: "Block bulk export of customer PII", description: "Exports over 1,000 customer rows — pending DPO sign-off.",
			effect: "deny", resource: "customer_record", action: "export", priority: 900, enabled: false, by: []who{both(dept("Information Security"), guardians)},
			condition: `{"attr":"context.row_count","op":"gt","value":1000}`},
	},
	"meridian": {
		{name: "US-only access to PHI", description: "HIPAA: protected health information is reached from US networks only.",
			effect: "deny", resource: "*", action: "*", priority: 1000, enabled: true, by: []who{both(dept("Security"), guardians)},
			condition: outside("US")},
		{name: "Charts outside the assigned unit", description: "Clinicians open charts in their own unit unless they break the glass.",
			effect: "deny", resource: "patient_record", action: "read", priority: 600, enabled: true, by: []who{both(dept("Security"), guardians)},
			condition: `{"all":[{"attr":"context.break_glass","op":"ne","value":true},{"attr":"resource.unit","op":"ne","value":{"attr":"subject.unit"}}]}`},
		{name: "Break-glass chart access", description: "Clinicians may open any chart in an emergency; every use is reviewed.",
			effect: "allow", resource: "patient_record", action: "read", priority: 500, enabled: true, by: []who{both(dept("Security"), guardians)},
			condition: `{"all":[{"attr":"context.break_glass","op":"eq","value":true},{"attr":"subject.title","op":"in","value":["Physician","Registered Nurse","Charge Nurse"]}]}`},
		{name: "E-prescribing requires MFA", description: "DEA EPCS: signing a prescription needs two factors.",
			effect: "deny", resource: "prescription", action: "sign", priority: 800, enabled: true, by: []who{both(dept("Security"), guardians)},
			condition: withoutMFA, edits: []abacEdit{{change: func(u *abac.UpdateInput) {
				u.Action = "*"
				u.Description = "DEA EPCS: any prescription action needs two factors."
			}}}},
		{name: "Float pool night-shift access", description: "Trial: float-pool nurses reach every unit at night.",
			effect: "allow", resource: "patient_record", action: "read", priority: 400, enabled: false, by: []who{both(dept("Security"), guardians)},
			condition: `{"all":[{"attr":"subject.team","op":"eq","value":"Float Pool"},{"any":[{"attr":"context.hour","op":"gte","value":19},{"attr":"context.hour","op":"lt","value":7}]}]}`,
			edits:     []abacEdit{{change: func(u *abac.UpdateInput) { u.Enabled = false }}}},
	},
	"lumen": {
		{name: "Staff-only workspace deletion", description: "Only Lumen staff may delete a customer workspace.",
			effect: "deny", resource: "workspace", action: "delete", priority: 700, enabled: true, by: []who{email("jonas.becker@lumenlabshq.dev")},
			condition: `{"not":{"attr":"subject.email","op":"suffix","value":"@lumenlabshq.dev"}}`},
		{name: "Free workspaces: three projects", description: "The free tier holds at most three projects.",
			effect: "deny", resource: "project", action: "create", priority: 300, enabled: true, by: []who{email("lucia.garcia@lumenlabshq.dev")},
			condition: `{"all":[{"attr":"resource.plan","op":"eq","value":"free"},{"attr":"resource.project_count","op":"gte","value":3}]}`,
			edits: []abacEdit{{change: func(u *abac.UpdateInput) {
				u.Condition = json.RawMessage(`{"all":[{"attr":"resource.plan","op":"eq","value":"free"},{"attr":"resource.project_count","op":"gte","value":5}]}`)
				u.Name, u.Description = "Free workspaces: five projects", "The free tier holds at most five projects (raised for the October launch)."
			}}}},
		{name: "EU data stays in the EU", description: "GDPR: exports only to EU regions.",
			effect: "deny", resource: "*", action: "export", priority: 900, enabled: true, by: []who{email("jonas.becker@lumenlabshq.dev")},
			condition: `{"all":[{"attr":"context.region","op":"exists"},{"attr":"context.region","op":"nin","value":["eu-west-1","eu-central-1"]}]}`},
	},
}

// limitChanges are the organizations that tightened their API limits.
var limitChanges = map[string][]limitChange{
	"northwind": {{[]who{both(dept("Information Security"), guardians)}, []limit{{"organization", 60, 300}, {"api_key", 20, 100}}}},
	"lumen": {
		{[]who{email("jonas.becker@lumenlabshq.dev")}, []limit{{"api_key", 25, 120}}},
		{[]who{email("jonas.becker@lumenlabshq.dev")}, []limit{{"api_key", 35, 150}, {"user", 20, 80}}},
	},
}
