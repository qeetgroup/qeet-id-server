package connections

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

// verifier is the PKCE code verifier of every printed authorize URL, so the
// printed token request redeems the code it returns.
const verifier = "seed-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

// hostedTest remembers a for the summary: the organization's app to sign in to
// through the hosted pages, or the device-flow app.
func (f *fed) hostedTest(o *world.Org, a *app) {
	h := hostedApp{org: o, name: a.spec.name, clientID: a.clientID, scopes: a.spec.scopes, note: a.spec.note}
	if !a.spec.public() {
		h.secret = a.secret
	}
	for _, r := range a.spec.redirects {
		if strings.HasPrefix(r, "http://localhost") || strings.HasPrefix(r, "http://127.0.0.1") {
			h.redirect = r
		}
	}
	for _, p := range append(o.Members(), o.Owner) {
		if p.Email == a.spec.tester {
			h.tester = p
		}
	}
	if a.spec.kind == "device" {
		h.tester = o.Owner
		if f.device == nil || o.Spec.Slug == "lumen" {
			f.device = &h
		}
		return
	}
	if h.redirect == "" || h.tester == nil {
		return
	}
	f.hosted = append(f.hosted, h)
}

// portal mints the organization's enterprise-setup links: the one Vertex's
// Okta administrator has open now, the one Northwind's used to rotate the SCIM
// token, and links that expired unused or were revoked.
func (f *fed) portal(o *world.Org) {
	w := f.w
	switch o.Spec.Slug {
	case "vertex":
		raw := f.portalLink(o, o.Owner, f.ago(30*time.Minute, 50*time.Minute), []string{"saml"}, 24*time.Hour, nil, false)
		f.portalURL, f.portalOrg = w.Deps.AdminPortal.Service.URL(raw), o.Spec.Name
	case "northwind":
		if use, ok := f.portalUses[o.ID]; ok {
			f.portalLink(o, use.by, use.at.Add(-25*time.Minute), []string{"scim"}, 2*time.Hour, &use.at, false)
		}
		t := w.WorkHours(w.Days(12), o.Loc)
		f.portalLink(o, adminAt(o, t), t, []string{"saml", "scim"}, time.Hour, nil, false)
	case "meridian":
		t := w.WorkHours(w.Days(30), o.Loc)
		f.portalLink(o, adminAt(o, t), t, []string{"saml"}, 4*time.Hour, nil, true)
		t = w.WorkHours(w.Days(64), o.Loc)
		f.portalLink(o, adminAt(o, t), t, []string{"scim"}, 24*time.Hour, nil, false)
	case "lumen":
		f.portalLink(o, o.Owner, w.WorkHours(o.Spec.Since.Add(5*day), o.Loc), []string{"saml"}, 24*time.Hour, nil, false)
	}
}

// portalLink makes a link at t as by, valid for ttl; used is when its holder
// opened it (nil: never), and revoke ends it ten minutes after it was made. It
// returns the raw token.
func (f *fed) portalLink(o *world.Org, by *world.Person, t time.Time, caps []string, ttl time.Duration, used *time.Time, revoke bool) string {
	w := f.w
	svc := w.Deps.AdminPortal.Service
	var id uuid.UUID
	var raw string
	w.At(t, func() {
		w.Tx("enterprise-setup link", func(tx pgx.Tx) error {
			l, token, err := svc.Generate(w.Ctx, tx, o.ID, by.ID, caps, ttl)
			if err == nil {
				id, raw = l.ID, token
			}
			return err
		})
		if used != nil {
			_, _, _, err := svc.Exchange(w.Ctx, raw)
			w.Check(err, "open enterprise-setup link")
		}
	})
	f.record(t, o, by, "admin_portal.link_generated", "admin_portal_link", &id, map[string]any{"capabilities": caps})
	// The API dates its expiry from the time it ran; date it from the story's.
	w.Exec("link expiry", `UPDATE organization.admin_portal_links SET expires_at = created_at + $3 * interval '1 second' WHERE id = $1 AND organization_id = $2`,
		id, o.ID, ttl.Seconds())
	if used != nil {
		w.Exec("link use", `UPDATE organization.admin_portal_links SET redeemed_at = $3, last_used_at = $4 WHERE id = $1 AND organization_id = $2`,
			id, o.ID, used.Add(-3*time.Minute), used.Add(4*time.Minute))
		w.Exec("portal session", `UPDATE auth.admin_portal_sessions SET created_at = $2, expires_at = $3, last_used_at = $4 WHERE link_id = $1`,
			id, used.Add(-3*time.Minute), used.Add(27*time.Minute), used.Add(4*time.Minute))
	}
	if revoke {
		at := t.Add(10 * time.Minute)
		w.At(at, func() {
			w.Tx("revoke enterprise-setup link", func(tx pgx.Tx) error { return svc.Revoke(w.Ctx, tx, o.ID, id) })
		})
		f.record(at, o, by, "admin_portal.link_revoked", "admin_portal_link", &id, nil)
	}
	return raw
}

// notes adds what testers need to the summary.
func (f *fed) notes() {
	w := f.w
	api, login := f.apiBase(), strings.TrimRight(w.Cfg.LoginBaseURL, "/")
	section := fmt.Sprintf("Hosted sign-in, one app per organisation (API %s, hosted pages %s)", api, login)
	w.Note(section, "Each URL signs in through the hosted pages and returns ?code=… to the app's loopback redirect (nothing listens:")
	w.Note(section, "copy the code from the address bar). PKCE verifier for every URL: %s", verifier)
	for _, h := range f.hosted {
		q := url.Values{
			"response_type": {"code"}, "client_id": {h.clientID}, "redirect_uri": {h.redirect},
			"scope": {strings.Join(h.scopes, " ")}, "state": {"seed-state-" + h.org.Spec.Slug}, "nonce": {"seed-nonce-" + h.org.Spec.Slug},
			"code_challenge": {codes.Hash(verifier)}, "code_challenge_method": {"S256"},
		}
		kind := "public, PKCE"
		auth := "-d client_id=" + h.clientID
		if h.secret != "" {
			kind = "confidential, secret " + h.secret
			auth = "-u " + h.clientID + ":" + h.secret
		}
		w.Note(section, "")
		w.Note(section, "%s · %s · %s (%s)", h.org.Spec.Name, h.name, h.clientID, kind)
		who := "  sign in as " + h.tester.Email
		if len(h.tester.MFA) > 0 {
			who += " (second factor: " + strings.Join(h.tester.MFA, ", ") + ")"
		}
		if h.note != "" {
			who += " — " + h.note
		}
		w.Note(section, "%s", who)
		w.Note(section, "  open: %s/v1/oauth/authorize?%s", api, q.Encode())
		w.Note(section, "  then: curl -s %s/v1/oauth/token-code %s -d grant_type=authorization_code -d redirect_uri=%s -d code_verifier=%s -d code=CODE",
			api, auth, h.redirect, verifier)
	}
	if d := f.device; d != nil {
		s := "Device flow: " + d.org.Spec.Name + " · " + d.name + " (" + d.clientID + ", public)"
		w.Note(s, "1. curl -s %s/v1/oauth/device_authorization -d client_id=%s -d 'scope=%s'", api, d.clientID, strings.Join(d.scopes, " "))
		w.Note(s, "2. open %s/device?user_code=USER_CODE and sign in as %s", login, d.tester.Email)
		w.Note(s, "3. curl -s %s/v1/oauth/token-code -d grant_type=%s -d client_id=%s -d device_code=DEVICE_CODE", api, deviceGrant, d.clientID)
	}
	const fedSection = "Federation"
	if f.portalURL != "" {
		w.Note(fedSection, "Enterprise-setup link (%s, SAML, 24h): %s", f.portalOrg, f.portalURL)
	}
	for _, s := range f.scim {
		w.Note(fedSection, "SCIM %-20s Authorization: Bearer %s  (%s/scim/v2/Users)", s.org, s.token, api)
	}
	if f.locked != "" {
		w.Note(fedSection, "Locked out for the next hour after wrong secrets: %s — Applications → Auth failures", f.locked)
	}
}
