package connections

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Grant types, as clients register them.
const (
	codeGrant     = "authorization_code"
	refreshGrant  = "refresh_token"
	deviceGrant   = "urn:ietf:params:oauth:grant-type:device_code"
	exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
)

var (
	webGrants    = []string{codeGrant, refreshGrant}
	userScopes   = []string{"openid", "profile", "email"}
	deviceGrants = []string{deviceGrant, refreshGrant}
)

// appSpec is an OIDC application an organization registered.
type appSpec struct {
	name, kind                string // kind: web, spa, native, device or m2m
	redirects, postLogout     []string
	backchannel, frontchannel string
	grants, scopes            []string
	pkceExempt                bool    // a legacy app given time to add PKCE
	users                     float64 // share of people who use it
	hosted                    bool    // the organization's hosted-test app
	tester                    string  // who signs in to it in the test
	note                      string
	resource                  [2]string // an API it serves: identifier, name
	reviewed                  bool      // a machine client the security team reviewed
	rotated                   bool      // its secret was rotated once
	lockout                   bool      // it is presenting a stale secret right now
}

func (s appSpec) public() bool { return s.kind == "spa" || s.kind == "native" || s.kind == "device" }

// catalogue is each organization's applications, by organization slug.
var catalogue = map[string][]appSpec{
	// Qeet Group's own products, each signing its staff in with Qeet ID the way
	// the Qeet ID SDKs do (a callback at /auth/callback), and the services
	// that call one product's API from another.
	"qeet": {
		{name: "Qeet Pay Console", kind: "web",
			redirects:   []string{"https://console.pay.qeet.in/auth/callback", "http://localhost:3010/auth/callback"},
			postLogout:  []string{"https://console.pay.qeet.in/", "http://localhost:3010/"},
			backchannel: "https://console.pay.qeet.in/auth/backchannel-logout",
			grants:      webGrants, scopes: []string{"openid", "profile", "email", "phone"}, users: 0.5,
			hosted: true, tester: "saibabu@qeet.in", resource: [2]string{"https://api.pay.qeet.in/", "Qeet Pay API"}},
		{name: "Qeet People", kind: "web", redirects: []string{"https://people.qeet.in/auth/callback"},
			postLogout: []string{"https://people.qeet.in/"}, backchannel: "https://people.qeet.in/auth/backchannel-logout",
			grants: webGrants, scopes: []string{"openid", "profile", "email", "phone"}, users: 0.9,
			resource: [2]string{"https://api.people.qeet.in/", "Qeet People API"}},
		{name: "Qeet AI Console", kind: "spa",
			redirects:  []string{"https://ai.qeet.in/auth/callback", "http://localhost:3020/auth/callback"},
			postLogout: []string{"https://ai.qeet.in/", "http://localhost:3020/"},
			grants:     []string{codeGrant}, scopes: userScopes, users: 0.3},
		{name: "Qeet Notify Console", kind: "web", redirects: []string{"https://notify.qeet.in/auth/callback"},
			postLogout: []string{"https://notify.qeet.in/"}, grants: webGrants, scopes: userScopes, users: 0.25,
			resource: [2]string{"https://notify.api.qeet.in/", "Qeet Notify API"}},
		{name: "Qeet Logs", kind: "web", redirects: []string{"https://logs.qeet.in/auth/callback"}, postLogout: []string{"https://logs.qeet.in/"},
			frontchannel: "https://logs.qeet.in/auth/frontchannel-logout", grants: webGrants, scopes: userScopes, users: 0.45,
			resource: [2]string{"https://api.logs.qeet.in/", "Qeet Logs API"}},
		{name: "Qeet Circle Staff Console", kind: "web", redirects: []string{"https://console.circle.qeet.in/auth/callback"},
			postLogout: []string{"https://console.circle.qeet.in/"}, backchannel: "https://console.circle.qeet.in/auth/backchannel-logout",
			grants: webGrants, scopes: userScopes, users: 0.15},
		{name: "Qeet CLI", kind: "device", grants: deviceGrants, scopes: userScopes},
		// Qeet Pay sends payment receipts and failed-payment notices through Qeet Notify.
		{name: "Qeet Pay → Qeet Notify", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"notify.send"}, reviewed: true},
		// Qeet People pays salaries through Qeet Pay on payroll day.
		{name: "Qeet People payroll → Qeet Pay", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"payouts.write", "payouts.read"}, reviewed: true, rotated: true},
		{name: "Billing Reconciler", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"billing.read", "invoices.write"}, reviewed: true},
		{name: "Support Desk (legacy)", kind: "web", redirects: []string{"https://support.qeet.in/auth/oidc/callback"},
			postLogout: []string{"https://support.qeet.in/"}, grants: webGrants, scopes: userScopes, users: 0.2, pkceExempt: true},
	},
	"qeet-sandbox": {
		{name: "Sandbox Playground", kind: "spa",
			redirects: []string{"http://localhost:5173/callback"}, postLogout: []string{"http://localhost:5173/"},
			grants: []string{codeGrant}, scopes: userScopes, hosted: true, tester: "saibabu@qeet.in"},
	},
	"northwind": {
		{name: "Loan Origination System", kind: "web",
			redirects:   []string{"https://los.northwindcapital.in/auth/callback", "http://localhost:4100/callback"},
			postLogout:  []string{"https://los.northwindcapital.in/signed-out", "http://localhost:4100/"},
			backchannel: "https://los.northwindcapital.in/auth/backchannel-logout",
			grants:      webGrants, scopes: userScopes, users: 0.55, hosted: true, tester: "rajesh.iyer@northwindcapital.in",
			resource: [2]string{"https://api.northwindcapital.in/loans", "Loan Servicing API"}},
		{name: "Collections Portal", kind: "web", redirects: []string{"https://collections.northwindcapital.in/oidc/callback"},
			postLogout: []string{"https://collections.northwindcapital.in/"}, grants: webGrants, scopes: userScopes, users: 0.3, pkceExempt: true},
		{name: "Core Banking Sync", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"loans.read", "customers.read"}, reviewed: true, rotated: true},
		{name: "Credit Bureau Connector", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"bureau.pull"}},
	},
	"meridian": {
		{name: "Meridian Staff Portal", kind: "web",
			redirects:    []string{"https://portal.meridianhealth.us/oidc/callback", "http://localhost:4200/callback"},
			postLogout:   []string{"https://portal.meridianhealth.us/", "http://localhost:4200/"},
			frontchannel: "https://portal.meridianhealth.us/oidc/frontchannel-logout",
			grants:       webGrants, scopes: userScopes, users: 0.6, hosted: true, tester: "jennifer.walsh@meridianhealth.us"},
		{name: "Staff Mobile", kind: "native", redirects: []string{"us.meridianhealth.staff:/oauth2redirect"},
			grants: webGrants, scopes: userScopes, users: 0.35},
		{name: "Claims Processor", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"claims.read", "claims.write"}, reviewed: true, resource: [2]string{"https://fhir.meridianhealth.us/r4", "FHIR R4 API"}},
		{name: "Nurse Scheduling (Kronos)", kind: "web", redirects: []string{"https://scheduling.meridianhealth.us/sso/oidc/callback"},
			grants: []string{codeGrant}, scopes: userScopes, users: 0.3},
	},
	"lumen": {
		{name: "Lumen Cloud", kind: "web",
			redirects:   []string{"https://app.lumenlabshq.dev/auth/callback", "http://localhost:4300/callback"},
			postLogout:  []string{"https://app.lumenlabshq.dev/", "http://localhost:4300/"},
			backchannel: "https://app.lumenlabshq.dev/auth/backchannel-logout",
			grants:      webGrants, scopes: userScopes, users: 0.7, hosted: true, tester: "jonas.becker@lumenlabshq.dev",
			resource: [2]string{"https://api.lumenlabshq.dev/", "Lumen Cloud API"}},
		{name: "Lumen Console", kind: "spa", redirects: []string{"https://console.lumenlabshq.dev/callback", "http://localhost:5174/callback"},
			postLogout: []string{"https://console.lumenlabshq.dev/"}, grants: []string{codeGrant}, scopes: userScopes, users: 0.5},
		{name: "lumen CLI", kind: "device", grants: deviceGrants, scopes: userScopes},
		{name: "Lumen Desktop", kind: "native", redirects: []string{"http://127.0.0.1/callback", "dev.lumenlabshq.desktop:/oauth/callback"},
			grants: webGrants, scopes: userScopes, users: 0.3},
		{name: "CI Deployer", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"deploy.write"}, lockout: true},
	},
	"aster": {
		{name: "Aster Store Admin", kind: "web",
			redirects:  []string{"https://admin.asterretail.in/auth/callback", "http://localhost:4400/callback"},
			postLogout: []string{"https://admin.asterretail.in/", "http://localhost:4400/"},
			grants:     webGrants, scopes: userScopes, users: 0.6, hosted: true, tester: "meera.shetty@asterretail.in"},
		{name: "Warehouse Scanner", kind: "spa", redirects: []string{"https://wms.asterretail.in/callback"},
			grants: []string{codeGrant}, scopes: userScopes, users: 0.5},
	},
	"vertex": {
		{name: "Vertex Load Board", kind: "web",
			redirects:  []string{"https://loadboard.vertexfreightco.us/callback", "http://localhost:4500/callback"},
			postLogout: []string{"http://localhost:4500/"}, grants: webGrants, scopes: userScopes, users: 0.4,
			hosted: true, tester: "tyler.morgan@vertexfreightco.us"},
	},
	"kestrel": {
		{name: "Kestrel Policy Desk", kind: "web",
			redirects:  []string{"https://desk.kestrelinsurance.in/callback", "http://localhost:4600/callback"},
			postLogout: []string{"http://localhost:4600/"}, grants: webGrants, scopes: userScopes, users: 0.6,
			hosted: true, tester: "sanjay.deshpande@kestrelinsurance.in",
			note: "expect address_not_allowed: sign-in only from the office network"},
	},
	"cobalt": {
		{name: "Cobalt Client Portal", kind: "spa",
			redirects:  []string{"https://clients.cobaltcreative.co.uk/callback", "http://localhost:4700/callback"},
			postLogout: []string{"http://localhost:4700/"}, grants: []string{codeGrant}, scopes: userScopes,
			hosted: true, tester: "oliver.bennett@cobaltcreative.co.uk"},
	},
}

// app is a registered application.
type app struct {
	org              *world.Org
	spec             appSpec
	id               uuid.UUID
	clientID, secret string
}

// applications registers the organization's OIDC applications, within its
// plan's limit, then the grants, consents and device sign-ins its people made.
func (f *fed) applications(o *world.Org) {
	w := f.w
	limit, err := w.Deps.Entitlement.Service.Limit(w.Ctx, o.ID, "apps")
	w.Check(err, "apps limit of "+o.Spec.Slug)
	count := 0
	for _, s := range catalogue[o.Spec.Slug] {
		if !slices.Contains(o.Spec.Features.Apps, s.kind) || (limit >= 0 && count >= limit) {
			continue
		}
		count++
		a := f.register(o, s)
		switch {
		case s.kind == "device":
			f.deviceSignIns(o, a)
			if f.device == nil || o.Spec.Slug == "lumen" {
				f.device = a
			}
		case s.kind != "m2m":
			f.grants(o, a)
		}
		if s.lockout {
			f.lockout(o, a)
		}
		if s.hosted {
			f.hosted = append(f.hosted, *a)
		}
	}
}

// register creates the application through the console's request, then what
// was changed since: the API it serves, a PKCE exemption, a rotated secret, a
// security review.
func (f *fed) register(o *world.Org, s appSpec) *app {
	w, by := f.w, o.Admin()
	typ := "confidential"
	if s.public() {
		typ = "public"
	}
	var out struct {
		Client       oidc.Client `json:"client"`
		ClientSecret string      `json:"client_secret"`
	}
	w.API.Do(o, by, "POST", base(o)+"/oidc/clients", oidc.CreateClientInput{Name: s.name, Type: typ, RedirectURIs: s.redirects,
		PostLogoutURIs: s.postLogout, GrantTypes: s.grants, Scopes: s.scopes, BackchannelLogoutURI: s.backchannel,
		FrontchannelLogoutURI: s.frontchannel}, &out)
	a := &app{org: o, spec: s, id: out.Client.ID, clientID: out.Client.ClientID, secret: out.ClientSecret}
	path := base(o) + "/oidc/clients/" + a.id.String()
	if s.resource[0] != "" {
		w.API.Do(o, by, "POST", base(o)+"/oidc/resources", oidc.CreateResourceInput{Identifier: s.resource[0], Name: s.resource[1], ServerClientID: a.clientID}, nil)
	}
	if s.pkceExempt {
		w.API.Do(o, by, "PATCH", path, map[string]any{"pkce_exempt_until": time.Now().Add(41 * 24 * time.Hour).Truncate(time.Hour)}, nil)
	}
	if s.rotated {
		var rotated struct {
			ClientSecret string `json:"client_secret"`
		}
		w.API.Do(o, by, "POST", path+"/rotate-secret", nil, &rotated)
		a.secret = rotated.ClientSecret
	}
	if s.reviewed {
		w.API.Do(o, o.First(world.InDept("Security"), world.HasRole(world.RoleAdmin)), "POST", path+"/review", nil, nil)
	}
	return a
}

// verifier is the PKCE code verifier of every printed authorize URL, so the
// printed token request redeems the code it returns.
const verifier = "seed-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

// challenge is v's S256 code challenge, as a client sends it (RFC 7636).
func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// grants signs the application's users in to it through the OIDC service:
// their consent and, where it renews, a refresh grant, some renewed since. On
// Lumen Desktop an old refresh token turns up again from another address and
// is caught as theft; on the hosted applications an administrator revokes one
// grant.
func (f *fed) grants(o *world.Org, a *app) {
	w, svc := f.w, f.w.Deps.OIDC.Service
	renews := slices.Contains(a.spec.grants, refreshGrant)
	most := 7 + w.Rand.IntN(10)
	var users []*world.Person
	for _, p := range o.Active() {
		if len(users) < most && !p.Unverified && (!a.spec.hosted || p.Email != a.spec.tester) && w.Chance(a.spec.users) {
			users = append(users, p)
		}
	}
	for i, p := range users {
		w.Check(svc.GrantConsent(w.Ctx, p.ID, a.clientID, a.spec.scopes), "consent to "+a.spec.name)
		if !renews {
			continue
		}
		v := w.Token(world.Alnum+"-._~", 64)
		code, _, err := svc.AuthorizeInLoginSession(w.Ctx, oidc.AuthorizeInput{UserID: p.ID, ClientID: a.clientID, RedirectURI: a.spec.redirects[0],
			Scopes: a.spec.scopes, Nonce: w.Token(world.Alnum, 22), CodeChallenge: challenge(v), CodeChallengeMethod: "S256", IP: p.Device.IP})
		w.Check(err, "authorize "+p.Email+" to "+a.spec.name)
		tok, err := svc.ExchangeCode(w.Ctx, a.clientID, a.secret, code, a.spec.redirects[0], v, "")
		w.Check(err, "redeem code for "+a.spec.name)
		// The old token turns up again from another address: theft.
		stolen := a.spec.name == "Lumen Desktop" && i == 0
		if w.Chance(0.4) || stolen {
			_, err := svc.RefreshToken(w.Ctx, a.clientID, a.secret, tok.RefreshToken, "")
			w.Check(err, "renew "+a.spec.name)
		}
		if stolen {
			if _, err := svc.RefreshToken(fromAddress(w.Ctx, world.Attackers[0].IP), a.clientID, "", tok.RefreshToken, ""); err == nil {
				w.Check(errors.New("replayed refresh token accepted"), "replay "+a.spec.name)
			}
		}
		if i == 2 && a.spec.hosted {
			f.revokeGrant(o, a, p)
		}
	}
}

// revokeGrant is an administrator ending p's grant to a in the console.
func (f *fed) revokeGrant(o *world.Org, a *app, p *world.Person) {
	page, err := f.w.Deps.OIDC.Service.ListGrants(f.w.Ctx, o.ID, &a.clientID, 100, paging.Cursor{})
	f.w.Check(err, "grants of "+a.spec.name)
	for _, g := range page.Items {
		if g.UserID == p.ID {
			f.w.API.Do(o, o.Admin(), "DELETE", base(o)+"/oauth/grants/"+g.ID.String(), nil, nil)
			return
		}
	}
}

// fromAddress is ctx as a request from ip carries it, so what a service audits
// deep inside records that address.
func fromAddress(ctx context.Context, ip string) context.Context {
	r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	r.RemoteAddr = ip + ":51234"
	out := ctx
	httpx.ClientIPContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { out = r.Context() })).ServeHTTP(nil, r)
	return out
}

// deviceSignIns is developers signing the CLI in on their machines through the
// device flow: most approved, one denied, one abandoned, and one waiting.
func (f *fed) deviceSignIns(o *world.Org, a *app) {
	w, svc := f.w, f.w.Deps.OIDC.Service
	i := 0
	for _, p := range o.Active() {
		if (p.Role != world.RoleDeveloper && p.Department != "Engineering") || p.Unverified || i > 6 {
			continue
		}
		raw, userCode, _, err := svc.DeviceAuthorize(w.Ctx, a.clientID, a.spec.scopes)
		w.Check(err, "device authorization for "+a.spec.name)
		switch i {
		case 3:
			w.Check(svc.DecideDevice(w.Ctx, p.ID, userCode, false, p.Device.IP), "deny device")
		case 5, 6: // abandoned, or still waiting for someone to enter the code
		default:
			w.Check(svc.DecideDevice(w.Ctx, p.ID, userCode, true, p.Device.IP), "approve device")
			_, err := svc.DeviceToken(w.Ctx, a.clientID, "", raw, p.Device.IP)
			w.Check(err, "collect device tokens")
		}
		i++
	}
}

// lockout is a deploy job still presenting an old secret:
// enough wrong secrets from the CI runner to lock the application out.
func (f *fed) lockout(o *world.Org, a *app) {
	w := f.w
	ctx := fromAddress(w.Ctx, "192.0.2.214") // the CI provider's egress address
	for range oidc.DefaultClientLockout().Threshold + 1 {
		if _, err := w.Deps.OIDC.Service.Introspect(ctx, a.clientID, "ci-"+w.Token(world.Alnum, 40), "", ""); err == nil {
			w.Check(errors.New("a wrong secret was accepted"), "lock out "+a.spec.name)
		}
	}
	f.locked = o.Spec.Name + " · " + a.spec.name + " (" + a.clientID + ")"
}

// note adds a's hosted sign-in test to the summary: the authorize URL and the
// token request that redeems its code.
func (a app) note(w *world.World, section, api string) {
	var redirect string
	for _, r := range a.spec.redirects {
		if strings.HasPrefix(r, "http://localhost") || strings.HasPrefix(r, "http://127.0.0.1") {
			redirect = r
		}
	}
	tester := a.org.Owner
	if p := w.Person(a.spec.tester); p != nil {
		tester = p
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {redirect}, "scope": {strings.Join(a.spec.scopes, " ")},
		"state": {"seed-state-" + a.org.Spec.Slug}, "nonce": {"seed-nonce-" + a.org.Spec.Slug},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	kind, auth := "public, PKCE", "-d client_id="+a.clientID
	if a.secret != "" {
		kind, auth = "confidential, secret "+a.secret, "-u "+a.clientID+":"+a.secret
	}
	who := "  sign in as " + tester.Email
	if len(tester.MFA) > 0 {
		who += " (second factor: " + strings.Join(tester.MFA, ", ") + ")"
	}
	if a.spec.note != "" {
		who += " — " + a.spec.note
	}
	w.Note(section, "")
	w.Note(section, "%s · %s · %s (%s)", a.org.Spec.Name, a.spec.name, a.clientID, kind)
	w.Note(section, "%s", who)
	w.Note(section, "  open: %s/v1/oauth/authorize?%s", api, q.Encode())
	w.Note(section, "  then: curl -s %s/v1/oauth/token %s -d grant_type=authorization_code -d redirect_uri=%s -d code_verifier=%s -d code=CODE",
		api, auth, redirect, verifier)
}
