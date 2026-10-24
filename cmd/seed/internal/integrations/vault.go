package integrations

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// secretSpec is a vault secret: its name, the integration it belongs to (the
// console's scope label), a value of the vendor's shape, and when it was
// stored and rotated.
type secretSpec struct {
	name, scope string
	value       func(w *world.World) string
	by          []who
	created     float64
	rotated     []float64 // days ago, oldest first
	revealed    float64   // days ago someone revealed it; 0 never
}

func prefixed(prefix string, n int) func(w *world.World) string {
	return func(w *world.World) string { return prefix + token(w, n) }
}

func hexed(n int) func(w *world.World) string {
	return func(w *world.World) string { return hexToken(w, n) }
}

// pem is a PEM private key, base64-encoded the way CI variables carry one.
func pem(w *world.World) string {
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + b64(w, 48) + "\n" + b64(w, 48) + "\n-----END RSA PRIVATE KEY-----\n"
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// secretSpecs are each organisation's vault secrets.
var secretSpecs = map[string][]secretSpec{
	"qeet": {
		{name: "RAZORPAY_KEY_SECRET", scope: "payments", value: prefixed("", 24), by: []who{email("diego@qeet.in")}, created: 300, rotated: []float64{120}},
		{name: "STRIPE_SECRET_KEY", scope: "payments", value: prefixed("sk_live_51P", 96), by: []who{email("diego@qeet.in")}, created: 280, rotated: []float64{150, 21}, revealed: 21},
		{name: "MSG91_AUTH_KEY", scope: "sms", value: prefixed("", 26), by: []who{email("rohan@qeet.in")}, created: 260},
		{name: "SLACK_BOT_TOKEN", scope: "alerts", value: prefixed("xoxb-5512398172-", 40), by: []who{both(team("Site Reliability"), builders)}, created: 240},
		{name: "PAGERDUTY_ROUTING_KEY", scope: "on-call", value: hexed(32), by: []who{both(team("Site Reliability"), builders)}, created: 238},
		{name: "GITHUB_APP_PRIVATE_KEY_B64", scope: "ci", value: pem, by: []who{email("rohan@qeet.in")}, created: 200, rotated: []float64{9}},
		{name: "ANTHROPIC_API_KEY", scope: "qeet-ai", value: prefixed("sk-ant-api03-", 80), by: []who{email("rohan@qeet.in")}, created: 90, revealed: 4},
	},
	"northwind": {
		{name: "CIBIL_API_KEY", scope: "credit-bureau", value: prefixed("", 32), by: []who{both(team("Platform Engineering"), builders)}, created: 320, rotated: []float64{140}},
		{name: "EXPERIAN_CLIENT_SECRET", scope: "credit-bureau", value: prefixed("", 40), by: []who{both(team("Platform Engineering"), builders)}, created: 310},
		{name: "NSDL_PAN_VERIFY_TOKEN", scope: "kyc", value: hexed(40), by: []who{both(team("Platform Engineering"), builders)}, created: 290},
		{name: "SPLUNK_HEC_TOKEN", scope: "siem", value: func(w *world.World) string { return uuid.NewSHA1(uuid.NameSpaceURL, []byte(token(w, 12))).String() }, by: []who{both(dept("Information Security"), builders)}, created: 300, rotated: []float64{30}},
		{name: "OKTA_API_TOKEN", scope: "identity", value: prefixed("00", 40), by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, created: 280, revealed: 2},
		{name: "KARIX_SMS_API_KEY", scope: "sms", value: prefixed("", 28), by: []who{both(team("Platform Engineering"), builders)}, created: 200},
	},
	"meridian": {
		{name: "EPIC_INTERCONNECT_CLIENT_SECRET", scope: "ehr", value: prefixed("", 48), by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 250, rotated: []float64{70}},
		{name: "SURESCRIPTS_API_KEY", scope: "e-prescribing", value: prefixed("", 32), by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 230},
		{name: "DATADOG_API_KEY", scope: "observability", value: hexed(32), by: []who{both(dept("Security"), builders)}, created: 200, rotated: []float64{2.2}},
		{name: "TWILIO_AUTH_TOKEN", scope: "patient-sms", value: hexed(32), by: []who{both(dept("Security"), builders)}, created: 180},
		{name: "SERVICENOW_INTEGRATION_PASSWORD", scope: "itsm", value: prefixed("", 20), by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 160, revealed: 33},
	},
	"lumen": {
		{name: "STRIPE_SECRET_KEY", scope: "billing", value: prefixed("sk_live_51O", 96), by: []who{both(team("Core Platform"), builders)}, created: 230, rotated: []float64{60}},
		{name: "POSTMARK_SERVER_TOKEN", scope: "email", value: func(w *world.World) string { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(token(w, 12))).String() }, by: []who{both(team("Core Platform"), builders)}, created: 220},
		{name: "GITHUB_APP_PRIVATE_KEY_B64", scope: "github-app", value: pem, by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 200},
		{name: "SENTRY_AUTH_TOKEN", scope: "observability", value: prefixed("sntrys_", 64), by: []who{both(team("Infrastructure"), builders)}, created: 150},
		{name: "CLOUDFLARE_API_TOKEN", scope: "infra", value: prefixed("", 40), by: []who{both(team("Infrastructure"), builders)}, created: 120, rotated: []float64{1.3}},
	},
	"aster": {
		{name: "SHOPIFY_ADMIN_API_TOKEN", scope: "storefront", value: prefixed("shpat_", 32), by: []who{email("meera.shetty@asterretail.in")}, created: 180},
		{name: "RAZORPAY_KEY_SECRET", scope: "payments", value: prefixed("", 24), by: []who{email("meera.shetty@asterretail.in")}, created: 175},
		{name: "DELHIVERY_API_TOKEN", scope: "shipping", value: hexed(40), by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 150},
		{name: "GUPSHUP_WHATSAPP_API_KEY", scope: "messaging", value: prefixed("sk_", 32), by: []who{email("meera.shetty@asterretail.in")}, created: 60},
	},
	"vertex": {
		{name: "OKTA_API_TOKEN", scope: "identity", value: prefixed("00", 40), by: []who{email("tyler.morgan@vertexfreightco.us")}, created: 6},
	},
}

// secrets stores the organisation's vault secrets through the secrets
// service, audited as the console does, and rotates and reveals some later.
func (d *dev) secrets(o *world.Org) {
	w := d.w
	for _, s := range secretSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		var sec *secret.Secret
		w.At(at, func() {
			var err error
			sec, err = w.Deps.Secret.Service.Create(w.Ctx, o.ID, s.name, s.scope, s.value(w))
			w.Check(err, "secret "+s.name)
			d.recordSecret(o, by, sec, "secret.created")
		})
		for _, days := range s.rotated {
			rt := d.when(o, days, by)
			rotator := person(o, rt, email(by.Email), builders)
			w.At(rt, func() {
				v := s.value(w)
				_, err := w.Deps.Secret.Service.Update(w.Ctx, o.ID, sec.ID, secret.UpdateInput{Value: &v})
				w.Check(err, "rotate "+s.name)
				d.recordSecret(o, rotator, sec, "secret.rotated")
			})
		}
		if s.revealed > 0 {
			rt := d.when(o, s.revealed, by)
			w.At(rt, func() { d.recordSecret(o, person(o, rt, email(by.Email), builders), sec, "secret.revealed") })
		}
	}
}

// recordSecret writes the audit row the secrets handler writes for action.
func (d *dev) recordSecret(o *world.Org, by *world.Person, s *secret.Secret, action string) {
	w := d.w
	w.Tx("audit "+action, func(tx pgx.Tx) error {
		return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, action, "secret", s.ID, map[string]any{"name": s.Name}))
	})
}

// vaultProvider is a third-party OAuth provider registered with the token
// vault, and who connected their accounts to it.
type vaultProvider struct {
	name, clientID, authorize, tokenPath, scopes string
	// lifetime of its access tokens; 0 when they don't expire.
	lifetime time.Duration
	refresh  bool
	users    who
	max      int
	account  func(w *world.World, p *world.Person) string
}

// vaultProviders are each organisation's token-vault providers. Browsers are
// sent to the vendor's real authorize page; the API exchanges codes through
// the organisation's own egress gateway, a host that does not resolve.
var vaultProviders = map[string][]vaultProvider{
	"qeet": {
		{name: "slack", clientID: "5512398172.7829104456213", authorize: "https://slack.com/oauth/v2/authorize", tokenPath: "/slack/api/oauth.v2.access",
			scopes: "chat:write channels:read users:read", users: func(p *world.Person) bool {
				return p.Department == "Customer Success" || p.Team == "Site Reliability" || p.Department == "Security"
			}, max: 12, account: slackUser},
		{name: "google-drive", clientID: "1048576302214-k3q9v2n8m1c7x5z4b6a0d2f8h1j3l5p7.apps.googleusercontent.com", authorize: "https://accounts.google.com/o/oauth2/v2/auth",
			tokenPath: "/google/token", scopes: "https://www.googleapis.com/auth/drive.readonly", lifetime: time.Hour, refresh: true,
			users: func(p *world.Person) bool {
				return p.Department == "Product" || p.Department == "Operations" || p.Department == "Design"
			}, max: 8, account: ownEmail},
		{name: "hubspot", clientID: "6b1f0c2e-58d4-4a8e-9f3b-2c7d1e9a4b60", authorize: "https://app.hubspot.com/oauth/authorize", tokenPath: "/hubspot/oauth/v1/token",
			scopes: "crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read", lifetime: 30 * time.Minute, refresh: true,
			users: dept("Sales"), max: 6, account: func(w *world.World, p *world.Person) string {
				return "portal:24917361/user:" + fmt.Sprint(60000000+w.Rand.IntN(9999999))
			}},
		{name: "zendesk", clientID: "qeet_id_token_vault", authorize: "https://qeetgroup.zendesk.com/oauth/authorizations/new", tokenPath: "/zendesk/oauth/tokens",
			scopes: "tickets:read users:read", users: team("Support"), max: 6, account: ownEmail},
	},
	"northwind": {
		{name: "salesforce", clientID: "3MVG9n_HvETGhr3Bq7xZ1pL0kTqWd8yR5uFs2cA6mJbNe4XoPiK", authorize: "https://login.salesforce.com/services/oauth2/authorize",
			tokenPath: "/salesforce/services/oauth2/token", scopes: "api refresh_token", lifetime: 2 * time.Hour, refresh: true,
			users: dept("Credit & Risk"), max: 8, account: func(w *world.World, p *world.Person) string { return "005" + token(w, 15) }},
		{name: "servicenow", clientID: "a6f0c41d3e9b4b7c8d2e5f1a0b9c7d3e", authorize: "https://northwindcapital.service-now.com/oauth_auth.do",
			tokenPath: "/servicenow/oauth_token.do", scopes: "useraccount", lifetime: 30 * time.Minute, refresh: true,
			users: team("IT Operations"), max: 4, account: ownEmail},
	},
	"meridian": {
		{name: "servicenow", clientID: "0d7e2c9b5a1f4e6d8c3b7a2f9e1d5c4b", authorize: "https://meridianhealth.service-now.com/oauth_auth.do",
			tokenPath: "/servicenow/oauth_token.do", scopes: "useraccount", lifetime: 30 * time.Minute, refresh: true,
			users: team("Service Desk"), max: 5, account: ownEmail},
	},
	"lumen": {
		{name: "github", clientID: "Iv23liQ8xZp4kT7wR2mN", authorize: "https://github.com/login/oauth/authorize", tokenPath: "/github/login/oauth/access_token",
			scopes: "repo read:org", lifetime: 8 * time.Hour, refresh: true, users: dept("Engineering"), max: 10,
			account: func(_ *world.World, p *world.Person) string {
				return strings.ReplaceAll(world.EmailLocal(p.First, p.Last), ".", "-")
			}},
		{name: "slack", clientID: "4408817265.7716209933480", authorize: "https://slack.com/oauth/v2/authorize", tokenPath: "/slack/api/oauth.v2.access",
			scopes: "chat:write channels:history users:read", users: func(*world.Person) bool { return true }, max: 9, account: slackUser},
		{name: "linear", clientID: "c2f9a1e0b7d84e3f9a6c5b2d1e0f7a8b", authorize: "https://linear.app/oauth/authorize", tokenPath: "/linear/oauth/token",
			scopes: "read write", lifetime: 24 * time.Hour, refresh: true, users: dept("Engineering"), max: 7, account: ownEmail},
		{name: "google-drive", clientID: "730214455829-p0q8r6s4t2u1v9w7x5y3z1a0b8c6d4e2.apps.googleusercontent.com", authorize: "https://accounts.google.com/o/oauth2/v2/auth",
			tokenPath: "/google/token", scopes: "https://www.googleapis.com/auth/drive.file", lifetime: time.Hour, refresh: true,
			users: dept("Go-to-Market"), max: 4, account: ownEmail},
	},
}

func ownEmail(_ *world.World, p *world.Person) string { return p.Email }

func slackUser(w *world.World, _ *world.Person) string {
	return "U0" + chars(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 9)
}

// egress is the organisation's outbound OAuth gateway, which never resolves.
func egress(o *world.Org) string { return "https://oauth-egress." + o.Spec.Domain }

// tokenVault registers the organisation's OAuth providers through the token
// vault service, then the accounts its people connected. A connection is only
// ever written by the OAuth callback, so those are written here, sealed the
// way the vault seals them.
func (d *dev) tokenVault(o *world.Org) {
	w := d.w
	for i, v := range vaultProviders[o.Spec.Slug] {
		at := d.when(o, d.jitter(float64(250-30*i)))
		w.At(at, func() {
			_, err := w.Deps.TokenVault.Service.RegisterProvider(w.Ctx, o.ID, tokenvault.RegisterProviderInput{
				Provider: v.name, ClientID: v.clientID, ClientSecret: token(w, 40),
				AuthorizeURL: v.authorize, TokenURL: egress(o) + v.tokenPath, Scopes: v.scopes,
			})
			w.Check(err, "token vault provider "+v.name)
		})
		for _, p := range people(o, w.Now, v.users) {
			if v.max == 0 {
				break
			}
			v.max--
			connected := d.when(o, w.Now.Sub(at).Hours()/24*w.Rand.Float64(), p)
			if connected.Before(at) {
				connected = at.Add(time.Duration(1+w.Rand.IntN(72)) * time.Hour)
			}
			d.grant(o, p, v, connected)
		}
	}
}

// grant writes p's connection to provider v, made at connected and last
// refreshed recently.
func (d *dev) grant(o *world.Org, p *world.Person, v vaultProvider, connected time.Time) {
	w := d.w
	resource := p.ID.String() + ":" + v.name
	accessCT, accessNonce, err := d.box.Seal(o.ID, "token-vault-access", resource, []byte(token(w, 56)))
	w.Check(err, "seal access token")
	var refreshCT, refreshNonce []byte
	if v.refresh {
		refreshCT, refreshNonce, err = d.box.Seal(o.ID, "token-vault-refresh", resource, []byte(token(w, 64)))
		w.Check(err, "seal refresh token")
	}
	updated := connected
	var expires *time.Time
	if v.lifetime > 0 {
		// Refreshed whenever an agent last asked for it; some have lapsed
		// since and will be refreshed on the next request.
		updated = w.Between(maxTime(connected, w.Days(3)), w.Now.Add(-15*time.Minute))
		e := updated.Add(v.lifetime)
		expires = &e
	}
	w.Exec("token vault connection", `
		INSERT INTO tenant.token_vault_grants
		    (tenant_id, user_id, provider, external_account_id, access_token_ct, access_token_nonce,
		     refresh_token_ct, refresh_token_nonce, token_type, scope, expires_at, created_at, updated_at, encryption_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Bearer', $9, $10, $11, $12, 1)`,
		o.ID, p.ID, v.name, v.account(w, p), accessCT, accessNonce, refreshCT, refreshNonce, v.scopes, expires, connected, updated)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
