package connections

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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

// appSpec is an OIDC application an organisation registered.
type appSpec struct {
	name, kind string // kind: web, spa, native, device or m2m
	// clientID and secret are fixed for the applications testers use; "" lets
	// the API mint them.
	clientID, secret          string
	redirects, postLogout     []string
	backchannel, frontchannel string
	grants, scopes            []string
	after                     time.Duration // after the organisation signed up
	pkceExempt                bool          // a legacy app given time to add PKCE
	users                     float64       // share of people who use it
	hosted                    bool          // the organisation's hosted-test app
	tester                    string        // who signs in to it in the test
	note                      string
	resource                  [2]string // an API it serves: identifier, name
	reviewed                  bool      // a machine client the security team reviewed
	rotated                   bool      // its secret was rotated once
	lockout                   bool      // it is presenting a stale secret right now
}

func (s appSpec) public() bool { return s.kind == "spa" || s.kind == "native" || s.kind == "device" }

const day = 24 * time.Hour

// catalogue is each organisation's applications, by organisation slug.
var catalogue = map[string][]appSpec{
	"qeet": {
		{name: "Example Web App", kind: "web", clientID: "qci_example_app", secret: "example-app-dev-secret-change-me",
			redirects: []string{"http://localhost:3010/api/auth/callback"}, postLogout: []string{"http://localhost:3010", "http://localhost:3010/"},
			grants: webGrants, scopes: userScopes, after: day, hosted: true, tester: "saibabu@qeet.in",
			note: "examples/nextjs-app"},
		{name: "Example SPA (React)", kind: "spa", clientID: "qci_example_spa",
			redirects: []string{"http://localhost:3020/callback"}, postLogout: []string{"http://localhost:3020", "http://localhost:3020/"},
			grants: []string{codeGrant}, scopes: userScopes, after: day + 10*time.Minute},
		{name: "Qeet Pay Dashboard", kind: "web",
			redirects: []string{"https://dashboard.pay.qeet.in/api/auth/callback/qeet-id"}, postLogout: []string{"https://dashboard.pay.qeet.in/"},
			backchannel: "https://dashboard.pay.qeet.in/api/auth/backchannel-logout",
			grants:      webGrants, scopes: []string{"openid", "profile", "email", "phone"}, after: 4 * day, users: 0.5,
			resource: [2]string{"https://api.pay.qeet.in/", "Qeet Pay API"}},
		{name: "Qeet Logs", kind: "web", redirects: []string{"https://logs.qeet.in/oauth2/callback"}, postLogout: []string{"https://logs.qeet.in/"},
			frontchannel: "https://logs.qeet.in/oauth2/frontchannel-logout", grants: webGrants, scopes: userScopes, after: 12 * day, users: 0.45},
		{name: "Qeet Mobile", kind: "native", redirects: []string{"in.qeet.mobile:/oauth2redirect"},
			grants: webGrants, scopes: []string{"openid", "profile", "email", "phone"}, after: 21 * day, users: 0.3},
		{name: "Qeet CLI", kind: "device", clientID: "qci_qeet_cli", grants: deviceGrants, scopes: userScopes, after: 35 * day},
		{name: "Billing Reconciler", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"billing.read", "invoices.write"},
			after: 50 * day, reviewed: true},
		{name: "Support Desk (legacy)", kind: "web", redirects: []string{"https://support.qeet.in/auth/oidc/callback"},
			postLogout: []string{"https://support.qeet.in/"}, grants: webGrants, scopes: userScopes, after: 64 * day, users: 0.2, pkceExempt: true},
	},
	"qeet-sandbox": {
		{name: "Sandbox Playground", kind: "spa", clientID: "qci_sandbox_playground",
			redirects: []string{"http://localhost:5173/callback"}, postLogout: []string{"http://localhost:5173/"},
			grants: []string{codeGrant}, scopes: userScopes, after: 2 * day, hosted: true, tester: "saibabu@qeet.in"},
	},
	"northwind": {
		{name: "Loan Origination System", kind: "web", clientID: "qci_northwind_los", secret: "northwind-los-dev-secret",
			redirects:   []string{"https://los.northwindcapital.in/auth/callback", "http://localhost:4100/callback"},
			postLogout:  []string{"https://los.northwindcapital.in/signed-out", "http://localhost:4100/"},
			backchannel: "https://los.northwindcapital.in/auth/backchannel-logout",
			grants:      webGrants, scopes: userScopes, after: 6 * day, users: 0.55, hosted: true, tester: "rajesh.iyer@northwindcapital.in",
			resource: [2]string{"https://api.northwindcapital.in/loans", "Loan Servicing API"}},
		{name: "Collections Portal", kind: "web", redirects: []string{"https://collections.northwindcapital.in/oidc/callback"},
			postLogout: []string{"https://collections.northwindcapital.in/"}, grants: webGrants, scopes: userScopes,
			after: 20 * day, users: 0.3, pkceExempt: true},
		{name: "Core Banking Sync", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"loans.read", "customers.read"},
			after: 9 * day, reviewed: true, rotated: true},
		{name: "Credit Bureau Connector", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"bureau.pull"}, after: 40 * day},
	},
	"meridian": {
		{name: "Meridian Staff Portal", kind: "web", clientID: "qci_meridian_portal", secret: "meridian-portal-dev-secret",
			redirects:    []string{"https://portal.meridianhealth.us/oidc/callback", "http://localhost:4200/callback"},
			postLogout:   []string{"https://portal.meridianhealth.us/", "http://localhost:4200/"},
			frontchannel: "https://portal.meridianhealth.us/oidc/frontchannel-logout",
			grants:       webGrants, scopes: userScopes, after: 5 * day, users: 0.6, hosted: true, tester: "jennifer.walsh@meridianhealth.us"},
		{name: "Staff Mobile", kind: "native", redirects: []string{"us.meridianhealth.staff:/oauth2redirect"},
			grants: webGrants, scopes: userScopes, after: 30 * day, users: 0.35},
		{name: "Claims Processor", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"claims.read", "claims.write"},
			after: 12 * day, reviewed: true, resource: [2]string{"https://fhir.meridianhealth.us/r4", "FHIR R4 API"}},
		{name: "Nurse Scheduling (Kronos)", kind: "web", redirects: []string{"https://scheduling.meridianhealth.us/sso/oidc/callback"},
			grants: []string{codeGrant}, scopes: userScopes, after: 45 * day, users: 0.3},
	},
	"lumen": {
		{name: "Lumen Cloud", kind: "web", clientID: "qci_lumen_cloud", secret: "lumen-cloud-dev-secret",
			redirects:   []string{"https://app.lumenlabshq.dev/auth/callback", "http://localhost:4300/callback"},
			postLogout:  []string{"https://app.lumenlabshq.dev/", "http://localhost:4300/"},
			backchannel: "https://app.lumenlabshq.dev/auth/backchannel-logout",
			grants:      webGrants, scopes: userScopes, after: 2 * day, users: 0.7, hosted: true, tester: "jonas.becker@lumenlabshq.dev",
			resource: [2]string{"https://api.lumenlabshq.dev/", "Lumen Cloud API"}},
		{name: "Lumen Console", kind: "spa", redirects: []string{"https://console.lumenlabshq.dev/callback", "http://localhost:5174/callback"},
			postLogout: []string{"https://console.lumenlabshq.dev/"}, grants: []string{codeGrant}, scopes: userScopes, after: 3 * day, users: 0.5},
		{name: "lumen CLI", kind: "device", clientID: "qci_lumen_cli", grants: deviceGrants, scopes: userScopes, after: 10 * day},
		{name: "Lumen Desktop", kind: "native", redirects: []string{"http://127.0.0.1/callback", "dev.lumenlabshq.desktop:/oauth/callback"},
			grants: webGrants, scopes: userScopes, after: 25 * day, users: 0.3},
		{name: "CI Deployer", kind: "m2m", grants: []string{exchangeGrant}, scopes: []string{"deploy.write"},
			after: 15 * day, lockout: true},
	},
	"aster": {
		{name: "Aster Store Admin", kind: "web", clientID: "qci_aster_store_admin", secret: "aster-admin-dev-secret",
			redirects:  []string{"https://admin.asterretail.in/auth/callback", "http://localhost:4400/callback"},
			postLogout: []string{"https://admin.asterretail.in/", "http://localhost:4400/"},
			grants:     webGrants, scopes: userScopes, after: 3 * day, users: 0.6, hosted: true, tester: "meera.shetty@asterretail.in"},
		{name: "Warehouse Scanner", kind: "spa", redirects: []string{"https://wms.asterretail.in/callback"},
			grants: []string{codeGrant}, scopes: userScopes, after: 20 * day, users: 0.5},
	},
	"vertex": {
		{name: "Vertex Load Board", kind: "web", clientID: "qci_vertex_loadboard", secret: "vertex-loadboard-dev-secret",
			redirects:  []string{"https://loadboard.vertexfreightco.us/callback", "http://localhost:4500/callback"},
			postLogout: []string{"http://localhost:4500/"}, grants: webGrants, scopes: userScopes, after: 2 * day, users: 0.4,
			hosted: true, tester: "tyler.morgan@vertexfreightco.us"},
	},
	"kestrel": {
		{name: "Kestrel Policy Desk", kind: "web", clientID: "qci_kestrel_policy_desk", secret: "kestrel-desk-dev-secret",
			redirects:  []string{"https://desk.kestrelinsurance.in/callback", "http://localhost:4600/callback"},
			postLogout: []string{"http://localhost:4600/"}, grants: webGrants, scopes: userScopes, after: 4 * day, users: 0.6,
			hosted: true, tester: "sanjay.deshpande@kestrelinsurance.in",
			note: "expect address_not_allowed: sign-in only from the office network"},
	},
	"cobalt": {
		{name: "Cobalt Client Portal", kind: "spa", clientID: "qci_cobalt_portal",
			redirects:  []string{"https://clients.cobaltcreative.co.uk/callback", "http://localhost:4700/callback"},
			postLogout: []string{"http://localhost:4700/"}, grants: []string{codeGrant}, scopes: userScopes, after: day,
			hosted: true, tester: "oliver.bennett@cobaltcreative.co.uk"},
	},
}

// app is a registered application.
type app struct {
	spec             appSpec
	id               uuid.UUID
	clientID, secret string
	created          time.Time
}

// applications registers the organisation's OIDC applications, within its
// plan's limit, then the grants, consents and device sign-ins its people made.
func (f *fed) applications(o *world.Org) {
	w := f.w
	limit, err := w.Deps.Entitlement.Service.Limit(w.Ctx, o.ID, "apps")
	w.Check(err, "apps limit of "+o.Spec.Slug)
	ip := f.allowedAddress(o)
	count := 0
	for _, s := range catalogue[o.Spec.Slug] {
		if !slices.Contains(o.Spec.Features.Apps, s.kind) || (limit >= 0 && count >= limit) {
			continue
		}
		at := o.Spec.Since.Add(s.after)
		if age := w.Now.Sub(o.Spec.Since); s.after > age/2 {
			at = o.Spec.Since.Add(age / 2 * time.Duration(1+count) / time.Duration(2+count))
		}
		a := f.register(o, adminAt(o, at), at, s)
		count++
		f.configure(o, a)
		switch {
		case s.kind == "device":
			f.deviceSignIns(o, a, ip)
		case s.kind != "m2m":
			f.grants(o, a, ip)
		}
		if s.lockout {
			f.lockout(o, a)
		}
		if s.hosted || s.kind == "device" {
			f.hostedTest(o, a)
		}
	}
	f.fixExpiries(o)
}

// register creates the application at t as by, pinning the fixed client ID and
// secret testers rely on.
func (f *fed) register(o *world.Org, by *world.Person, t time.Time, s appSpec) *app {
	w := f.w
	typ := "confidential"
	if s.public() {
		typ = "public"
	}
	a := &app{spec: s, created: t}
	w.At(t, func() {
		w.Tx("register "+s.name, func(tx pgx.Tx) error {
			c, secret, err := w.Deps.OIDC.Service.RegisterClient(w.Ctx, tx, oidc.CreateClientInput{
				TenantID: o.ID, Name: s.name, Type: typ, RedirectURIs: s.redirects, PostLogoutURIs: s.postLogout,
				GrantTypes: s.grants, Scopes: s.scopes, BackchannelLogoutURI: s.backchannel, FrontchannelLogoutURI: s.frontchannel,
			})
			if err != nil {
				return err
			}
			a.id, a.clientID, a.secret = c.ID, c.ClientID, secret
			if s.clientID == "" {
				return nil
			}
			a.clientID = s.clientID
			var hash *string
			if typ == "confidential" {
				a.secret = s.secret
				h := password.HashSecret(s.secret)
				hash = &h
			}
			_, err = tx.Exec(w.Ctx, `UPDATE auth.oidc_clients SET client_id = $3, client_secret_hash = $4 WHERE id = $1 AND tenant_id = $2`,
				c.ID, o.ID, s.clientID, hash)
			return err
		})
	})
	f.record(t, o, by, "oidc.client_registered", "oidc_client", &a.id, map[string]any{
		"client_id": a.clientID, "type": typ, "name": s.name, "grant_types": s.grants, "scopes": s.scopes})
	return a
}

// configure applies what was changed after registration: the API the
// application serves, a PKCE exemption, a rotated secret, a security review.
func (f *fed) configure(o *world.Org, a *app) {
	w, s := f.w, a.spec
	svc := w.Deps.OIDC.Service
	if s.resource[0] != "" {
		t := a.created.Add(26 * time.Hour)
		by := adminAt(o, t)
		var id uuid.UUID
		w.At(t, func() {
			w.Tx("resource "+s.resource[1], func(tx pgx.Tx) error {
				r, err := svc.CreateResource(w.Ctx, tx, o.ID, oidc.CreateResourceInput{Identifier: s.resource[0], Name: s.resource[1], ServerClientID: a.clientID})
				if err == nil {
					id = r.ID
				}
				return err
			})
		})
		f.record(t, o, by, "oidc.resource_registered", "oidc_resource", &id, map[string]any{"identifier": s.resource[0]})
	}
	if s.pkceExempt {
		t := later(w.WorkHours(w.Days(20), o.Loc), a.created.Add(time.Hour))
		until := w.Now.Add(41 * day).Truncate(time.Hour)
		by := adminAt(o, t)
		var c *oidc.Client
		w.At(t, func() {
			w.Tx("PKCE exemption "+s.name, func(tx pgx.Tx) error {
				var err error
				c, err = svc.UpdateClient(w.Ctx, tx, o.ID, a.id, oidc.UpdateClientInput{PKCEExemptUntil: oidc.OptionalTime{Set: true, At: &until}})
				return err
			})
		})
		f.record(t, o, by, "oidc.client_updated", "oidc_client", &a.id, map[string]any{"client_id": a.clientID, "name": c.Name, "pkce_exempt_until": until})
	}
	if s.rotated {
		t := later(w.WorkHours(w.Days(75), o.Loc), a.created.Add(day))
		by := adminAt(o, t)
		w.At(t, func() {
			w.Tx("rotate "+s.name, func(tx pgx.Tx) error {
				var err error
				a.secret, _, err = svc.RotateClientSecret(w.Ctx, tx, o.ID, a.id)
				return err
			})
		})
		f.record(t, o, by, "oidc.client_secret_rotated", "oidc_client", &a.id, map[string]any{"client_id": a.clientID})
	}
	if s.reviewed {
		t := a.created.Add(2*day + 3*time.Hour)
		reviewer := adminAt(o, t)
		for _, p := range o.Admins() {
			if p.Department == "Security" && p.Joined.Before(t) {
				reviewer = p // the security lead, who administers the organisation
				break
			}
		}
		w.At(t, func() {
			w.Check(svc.ReviewShadowAIClient(w.Ctx, o.ID, a.id, reviewer.ID), "review "+s.name)
		})
	}
}

// allowedAddress is an address the organisation's address rules let sign in,
// or "" when it has none switched on.
func (f *fed) allowedAddress(o *world.Org) string {
	w := f.w
	var enabled bool
	err := w.Admin.QueryRow(w.Ctx, `SELECT enabled FROM tenant.ip_rules_config WHERE tenant_id = $1`, o.ID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return ""
	}
	w.Check(err, "address rules of "+o.Spec.Slug)
	var cidr string
	err = w.Admin.QueryRow(w.Ctx, `SELECT cidr FROM tenant.ip_rules WHERE tenant_id = $1 AND action = 'allow' ORDER BY created_at LIMIT 1`, o.ID).Scan(&cidr)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	w.Check(err, "allow rule of "+o.Spec.Slug)
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		addr, aerr := netip.ParseAddr(cidr)
		w.Check(aerr, "parse allow rule "+cidr)
		return addr.String()
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return prefix.Addr().String()
	}
	return prefix.Masked().Addr().Next().String()
}

// users is who signed in to a: a share of the organisation's people, the
// testers excepted on the application they test, so its consent screen shows.
func (f *fed) users(o *world.Org, a *app) []*world.Person {
	w := f.w
	most := 7 + w.Rand.IntN(10)
	var out []*world.Person
	for _, p := range o.Active() {
		if p.Unverified || (a.spec.hosted && p.Email == a.spec.tester) || !w.Chance(a.spec.users) {
			continue
		}
		out = append(out, p)
		if len(out) == most {
			break
		}
	}
	return out
}

// grants signs the application's users in to it: their consent and, where it
// renews, a refresh grant started within the organisation's grant lifetime,
// some renewed since, one revoked by an administrator and, on Lumen Desktop, a
// replayed refresh token caught as theft.
func (f *fed) grants(o *world.Org, a *app, ip string) {
	w := f.w
	svc := w.Deps.OIDC.Service
	life := f.grantLifetime(o)
	renews := slices.Contains(a.spec.grants, refreshGrant)
	revoked, stolen := false, false
	for i, p := range f.users(o, a) {
		from := later(a.created, p.Joined).Add(time.Hour)
		if renews {
			from = later(from, w.Now.Add(-life*8/10))
		}
		to := w.Now.Add(-2 * time.Hour)
		if !from.Before(to) {
			continue
		}
		t := f.workTime(from, to, p.Loc)
		if !renews {
			w.At(t, func() { w.Check(svc.GrantConsent(w.Ctx, p.ID, a.clientID, a.spec.scopes), "consent to "+a.spec.name) })
			continue
		}
		raw := f.signIn(o, a, p, t, ip)
		if raw == "" {
			continue
		}
		if w.Chance(0.4) {
			t2 := later(w.Between(t.Add(time.Hour), w.Now.Add(-20*time.Minute)), t.Add(time.Hour))
			if t2.Before(w.Now.Add(-10 * time.Minute)) {
				old := raw
				w.At(t2, func() {
					tok, err := svc.RefreshToken(w.Ctx, a.clientID, a.secret, raw, "")
					w.Check(err, "renew "+a.spec.name)
					raw = tok.RefreshToken
				})
				if a.spec.name == "Lumen Desktop" && !stolen {
					// The old token turns up again from another address: theft.
					t3 := later(t2.Add(3*time.Hour), w.Now.Add(-30*time.Hour))
					if t3.Before(w.Now.Add(-time.Hour)) {
						w.At(t3, func() {
							_, err := svc.RefreshToken(fromAddress(w.Ctx, world.Attackers[0].IP), a.clientID, "", old, "")
							if err == nil {
								w.Check(errors.New("replayed refresh token accepted"), "replay "+a.spec.name)
							}
						})
						stolen = true
					}
				}
			}
		}
		if !revoked && i >= 2 && (a.spec.name == "Qeet Pay Dashboard" || a.spec.hosted) {
			f.revokeGrant(o, a, p, later(t.Add(4*time.Hour), w.Now.Add(-3*day)))
			revoked = true
		}
	}
}

// signIn is p signing in to a at t through the authorization-code flow; it
// returns the refresh token, or "" when the organisation's rules refused it.
func (f *fed) signIn(o *world.Org, a *app, p *world.Person, t time.Time, ip string) string {
	w := f.w
	svc := w.Deps.OIDC.Service
	verifier := f.token(alnum+"-._~", 64)
	var raw string
	w.At(t, func() {
		w.Check(svc.GrantConsent(w.Ctx, p.ID, a.clientID, a.spec.scopes), "consent to "+a.spec.name)
		code, _, err := svc.AuthorizeInLoginSession(w.Ctx, oidc.AuthorizeInput{
			UserID: p.ID, ClientID: a.clientID, RedirectURI: a.spec.redirects[0], Scopes: a.spec.scopes,
			Nonce: f.token(alnum, 22), CodeChallenge: codes.Hash(verifier), CodeChallengeMethod: "S256", IP: ip,
		})
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			return
		}
		w.Check(err, "authorize "+p.Email+" to "+a.spec.name)
		tok, err := svc.ExchangeCode(w.Ctx, a.clientID, a.secret, code, a.spec.redirects[0], verifier, "")
		w.Check(err, "redeem code for "+a.spec.name)
		raw = tok.RefreshToken
	})
	return raw
}

// revokeGrant is an administrator ending p's grant to a at t.
func (f *fed) revokeGrant(o *world.Org, a *app, p *world.Person, t time.Time) {
	w := f.w
	if t.After(w.Now.Add(-time.Hour)) {
		return
	}
	var id uuid.UUID
	err := w.Admin.QueryRow(w.Ctx, `SELECT id FROM auth.oidc_refresh_tokens
		WHERE tenant_id = $1 AND client_id = $2 AND user_id = $3 AND revoked_at IS NULL AND replaced_by IS NULL
		ORDER BY issued_at DESC LIMIT 1`, o.ID, a.clientID, p.ID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	w.Check(err, "find grant to revoke")
	by := adminAt(o, t)
	w.At(t, func() {
		w.Tx("revoke grant", func(tx pgx.Tx) error {
			_, _, err := w.Deps.OIDC.Service.RevokeGrant(w.Ctx, tx, o.ID, id)
			return err
		})
	})
	uid := p.ID
	f.record(t, o, by, "oauth.grant_revoked", "oidc_grant", &uid, map[string]any{"client_id": a.clientID})
}

// deviceSignIns is developers signing the CLI in on their machines: most
// approved, one denied, a few abandoned, and one waiting right now.
func (f *fed) deviceSignIns(o *world.Org, a *app, ip string) {
	w := f.w
	svc := w.Deps.OIDC.Service
	var devs []*world.Person
	for _, p := range o.Active() {
		if (p.Role == world.RoleDeveloper || p.Department == "Engineering") && !p.Unverified {
			devs = append(devs, p)
		}
	}
	if len(devs) == 0 {
		return
	}
	// start shows the code on the device at t, which polls once; the person
	// decides on the hosted /device page a little later. The code's expiry is
	// dated from the story afterwards (fixExpiries), so a later step still
	// finds it live now.
	start := func(t time.Time) (raw, userCode string) {
		w.At(t, func() {
			var err error
			raw, userCode, _, err = svc.DeviceAuthorize(w.Ctx, a.clientID, a.spec.scopes)
			w.Check(err, "device authorization for "+a.spec.name)
			if _, err := svc.DeviceToken(w.Ctx, a.clientID, "", raw, ip); err == nil {
				w.Check(errors.New("an undecided device code issued tokens"), "poll "+a.spec.name)
			}
		})
		return raw, userCode
	}
	for i, p := range devs {
		if i >= 9 {
			break
		}
		from := later(later(a.created, p.Joined).Add(time.Hour), w.Now.Add(-f.grantLifetime(o)*7/10))
		if !from.Before(w.Now.Add(-3 * time.Hour)) {
			continue
		}
		t := f.workTime(from, w.Now.Add(-3*time.Hour), p.Loc)
		raw, userCode := start(t)
		decided := t.Add(time.Duration(25+w.Rand.IntN(90)) * time.Second)
		switch i {
		case 3:
			w.At(decided, func() { w.Check(svc.DecideDevice(w.Ctx, p.ID, userCode, false, p.Device.IP), "deny device") })
		case 5, 7:
			// Abandoned: nobody entered the code.
		default:
			w.At(decided, func() {
				w.Check(svc.DecideDevice(w.Ctx, p.ID, userCode, true, p.Device.IP), "approve device")
				_, err := svc.DeviceToken(w.Ctx, a.clientID, "", raw, ip)
				w.Check(err, "collect device tokens")
			})
		}
	}
	if o.Spec.Slug == "lumen" {
		// Waiting for someone to enter the code on the hosted /device page.
		start(f.ago(2*time.Minute, 4*time.Minute))
	}
}

// lockout is a deploy job still presenting the secret replaced last week: a
// few wrong secrets two days ago, then enough in the last quarter-hour to lock
// the application out for the next hour.
func (f *fed) lockout(o *world.Org, a *app) {
	w := f.w
	svc := w.Deps.OIDC.Service
	runner := "192.0.2.214" // the CI provider's egress address
	wrong := "ci-" + f.token(alnum, 40)
	fail := func(t time.Time) {
		w.At(t, func() {
			_, err := svc.Introspect(fromAddress(w.Ctx, runner), a.clientID, wrong, "", "")
			if err == nil {
				w.Check(errors.New("a wrong secret was accepted"), "lock out "+a.spec.name)
			}
		})
	}
	earlier := f.around(w.Days(2))
	for i := range 3 {
		fail(earlier.Add(time.Duration(i*90) * time.Second))
	}
	svc.SetClientLockout(oidc.ClientLockout{Threshold: w.Cfg.ClientAuthLockoutThreshold, Window: w.Cfg.ClientAuthLockoutWindow, Duration: time.Hour})
	for i := range w.Cfg.ClientAuthLockoutThreshold {
		fail(w.Now.Add(-11*time.Minute + time.Duration(i*40)*time.Second))
	}
	svc.SetClientLockout(oidc.ClientLockout{Threshold: w.Cfg.ClientAuthLockoutThreshold, Window: w.Cfg.ClientAuthLockoutWindow, Duration: w.Cfg.ClientAuthLockoutDuration})
	f.locked = o.Spec.Name + " · " + a.spec.name + " (" + a.clientID + ")"
}

// grantLifetime is how long the organisation lets an application's grant last:
// its maximum session age, or the platform's.
func (f *fed) grantLifetime(o *world.Org) time.Duration {
	w := f.w
	var secs float64
	err := w.Admin.QueryRow(w.Ctx, `SELECT EXTRACT(EPOCH FROM session_max_age) FROM tenant.security_policies WHERE tenant_id = $1`, o.ID).Scan(&secs)
	if err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return w.Cfg.SessionMaxAge
}

// fixExpiries dates the expiries the API set as "now + lifetime" from when
// each row was made in the story: the API stamped them at run time, and At
// moves only timestamps near that time.
func (f *fed) fixExpiries(o *world.Org) {
	w := f.w
	life := f.grantLifetime(o)
	w.Exec("refresh token expiries", `
		UPDATE auth.oidc_refresh_tokens t
		SET grant_expires_at = g.started + $2 * interval '1 second',
		    expires_at = LEAST(t.issued_at + $3 * interval '1 second', g.started + $2 * interval '1 second')
		FROM (SELECT grant_id, min(issued_at) AS started FROM auth.oidc_refresh_tokens WHERE tenant_id = $1 GROUP BY grant_id) g
		WHERE t.tenant_id = $1 AND t.grant_id = g.grant_id`, o.ID, life.Seconds(), w.Cfg.RefreshTokenTTL.Seconds())
	w.Exec("device code expiries", `UPDATE auth.oidc_device_codes SET expires_at = created_at + interval '10 minutes' WHERE tenant_id = $1`, o.ID)
	w.Exec("authorization code expiries", `UPDATE auth.oidc_authorization_codes SET expires_at = created_at + interval '10 minutes' WHERE tenant_id = $1`, o.ID)
}
