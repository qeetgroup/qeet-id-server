// Package integrations seeds each organization's integrations: API keys,
// service principals, AI agents, secrets, token-vault providers, verifiable
// credentials, ABAC policies, relationship tuples, rate-limit overrides, auth
// hooks, log streaming and webhooks.
package integrations

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey"
	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// section is the summary section for what testers can call.
const section = "API keys and machine credentials"

// Seed builds every organization's integrations.
func Seed(w *world.World) {
	for _, o := range w.Orgs {
		apiKeys(w, o)
		principals(w, o)
		agents(w, o)
		secrets(w, o)
		tokenVault(w, o)
		credentials(w, o)
		policies(w, o)
		rebac(w, o)
		rateLimits(w, o)
		authHooks(w, o)
		logSinks(w, o)
		webhooks(w, o)
	}
	const s = "Developer screens (Qeet Group as saibabu@qeet.in)"
	w.Note(s, "Webhooks: active and disabled; endpoints don't resolve, so once the server runs its deliveries fail with \"no such host\".")
	w.Note(s, "API keys: expiring soon, revoked (leaked Statuspage key); agents active/suspended/decommissioned; secrets rotated.")
	w.Note(s, "ABAC versions: \"Contractors: business hours only\" (3); ReBAC: object document:readme (Qeet, Lumen, Northwind, Meridian).")
	w.Note(s, "Auth hooks: enabled fail-open at Northwind and Meridian — a sign-in there records auth_hook.skipped; Qeet's are off.")
	w.Note(s, "Log streaming: Qeet HTTP, Northwind Splunk HEC + old ArcSight (off), Meridian Datadog.")
}

// issuer is who creates a credential carrying scopes: the first preferred
// person, then an Admin, allowed to (the server refuses a scope its creator
// doesn't hold), else the owner.
func issuer(w *world.World, o *world.Org, scopes []string, prefs ...who) *world.Person {
	for _, pref := range append(prefs, role(world.RoleAdmin)) {
		for _, p := range append(o.Active(), o.Guests...) {
			organization, id := o.ID, p.ID
			caller := &httpx.Principal{UserID: &id, OrganizationID: &organization, ActorType: "user"}
			if pref(p) && w.Deps.RBAC.Repo.CheckGrantScopes(w.Ctx, caller, o.ID, scopes) == nil {
				return p
			}
		}
	}
	return o.Owner
}

// apiKeys creates the organization's API keys through the API key service,
// and revokes the ones that were.
func apiKeys(w *world.World, o *world.Org) {
	for _, k := range keys[o.Spec.Slug] {
		by := issuer(w, o, k.scopes, k.by...)
		in := apikey.CreateInput{OrganizationID: o.ID, Name: k.name, Scopes: k.scopes, Actor: by.Actor()}
		if k.personal {
			in.UserID = &by.ID
		}
		if k.expires != 0 {
			exp := time.Now().Add(time.Duration(k.expires * float64(24*time.Hour))).Truncate(time.Minute)
			in.ExpiresAt = &exp
		}
		key, raw, err := w.Deps.APIKey.Service.Create(w.Ctx, in)
		w.Check(err, "API key "+k.name)
		if k.revoked {
			w.Check(w.Deps.APIKey.Service.Revoke(w.Ctx, o.ID, key.ID, o.First(append(k.revoker, email(by.Email))...).Actor()), "revoke "+k.name)
		}
		if k.print {
			w.Note(section, "%s — API key %q (%v)", o.Spec.Name, k.name, k.scopes)
			w.Note(section, "  curl -H 'Authorization: ApiKey %s' '%s/v1/users?limit=5'", raw, w.BaseURL())
		}
	}
}

// principals creates the organization's service principals in the console,
// and disables the retired ones.
func principals(w *world.World, o *world.Org) {
	for _, s := range principalSpecs[o.Spec.Slug] {
		by := issuer(w, o, s.scopes, s.by...)
		var out struct {
			ClientID     uuid.UUID `json:"client_id"`
			ClientSecret string    `json:"client_secret"`
		}
		w.API.Do(o, by, "POST", "/service-principals", principal.CreateInput{Name: s.name, Description: s.description, Scopes: s.scopes}, &out)
		if s.disabled {
			w.API.Do(o, by, "DELETE", "/service-principals/"+out.ClientID.String(), nil, nil)
		}
		if s.print {
			w.Note(section, "%s — service principal %q: client_id %s  client_secret %s", o.Spec.Name, s.name, out.ClientID, out.ClientSecret)
			w.Note(section, "  curl -u '%s:%s' -d grant_type=client_credentials %s/v1/oauth/token", out.ClientID, out.ClientSecret, w.BaseURL())
		}
	}
}

// agents registers the organization's AI agents with their sponsors, then
// suspends or decommissions the ones whose story ends that way.
func agents(w *world.World, o *world.Org) {
	for i, s := range agentSpecs[o.Spec.Slug] {
		by := issuer(w, o, s.scopes, s.by...)
		a, err := w.Deps.Agent.Service.Create(w.Ctx, o.ID, s.name, s.scopes, s.ttl, o.First(s.sponsor...).ID, by.Actor())
		w.Check(err, "agent "+s.name)
		if s.end != "" {
			ender := o.First(both(dept("Security"), guardians), both(dept("Information Security"), guardians), email(by.Email))
			_, err := w.Deps.Agent.Service.Transition(w.Ctx, a.ID, o.ID, s.end, ender.Actor())
			w.Check(err, s.end+" agent "+s.name)
		} else if o.Spec.Slug == "qeet" && i == 1 {
			w.Note(section, "%s — agent %q: curl -u '%s:%s' -d grant_type=client_credentials %s/v1/oauth/token",
				o.Spec.Name, s.name, a.ID, a.Secret, w.BaseURL())
		}
	}
}

// secrets stores the organization's vault secrets in the console, then
// rotates and reveals some.
func secrets(w *world.World, o *world.Org) {
	for _, s := range secretSpecs[o.Spec.Slug] {
		by := o.First(s.by...)
		body := map[string]any{"name": s.name, "scope": s.scope, "value": s.value(w)}
		if s.rotateEvery > 0 {
			body["rotation_interval_days"] = s.rotateEvery
		}
		var sec struct {
			ID uuid.UUID `json:"id"`
		}
		path := "/organizations/" + o.ID.String() + "/secrets"
		w.API.Do(o, by, "POST", path, body, &sec)
		for range s.rotations {
			w.API.Do(o, by, "PATCH", path+"/"+sec.ID.String(), map[string]any{"value": s.value(w)}, nil)
		}
		if s.revealed {
			w.API.Do(o, by, "POST", path+"/"+sec.ID.String()+"/reveal", nil, nil)
		}
	}
}

// tokenVault registers the organization's OAuth providers with the token vault.
func tokenVault(w *world.World, o *world.Org) {
	for _, v := range vaultProviders[o.Spec.Slug] {
		_, err := w.Deps.TokenVault.Service.RegisterProvider(w.Ctx, o.ID, tokenvault.RegisterProviderInput{
			Provider: v.name, ClientID: v.clientID, ClientSecret: w.Token(world.Alnum, 40),
			AuthorizeURL: v.authorize, TokenURL: "https://oauth-egress." + o.Spec.Domain + v.tokenPath, Scopes: v.scopes,
		})
		w.Check(err, "token vault provider "+v.name)
	}
}

// credentials issues the organization's verifiable credentials; one is
// revoked after its holder lost their laptop, and issued again.
func credentials(w *world.World, o *world.Org) {
	svc := w.Deps.VC.Service
	by := o.First(both(dept("Security"), guardians), both(dept("Information Security"), guardians), role(world.RoleAdmin))
	for _, s := range credentialSpecs[o.Spec.Slug] {
		var first uuid.UUID
		var holder *world.Person
		n := 0
		for _, p := range o.Active() {
			if n == s.max || !s.to(p) {
				continue
			}
			n++
			in := vc.IssueInput{Subject: "did:web:" + o.Spec.Domain + ":people:" + strings.ToLower(p.EmployeeID), Type: s.typ,
				Claims: s.claims(p), TTLSeconds: int(s.ttl * 86400), UserID: &p.ID}
			res, err := svc.Issue(w.Ctx, o.ID, in, by.Actor())
			w.Check(err, "credential "+s.typ)
			if first == uuid.Nil {
				first, holder = res.CredentialID, p
			}
		}
		if s.revoke && holder != nil {
			w.Check(svc.Revoke(w.Ctx, first, o.ID, by.Actor()), "revoke "+s.typ)
			in := vc.IssueInput{Subject: "did:web:" + o.Spec.Domain + ":people:" + strings.ToLower(holder.EmployeeID), Type: s.typ,
				Claims: s.claims(holder), TTLSeconds: int(s.ttl * 86400), UserID: &holder.ID}
			_, err := svc.Issue(w.Ctx, o.ID, in, by.Actor())
			w.Check(err, "reissue "+s.typ)
		}
	}
}

// consoleResources are the resource types of Qeet ID's own permissions, which
// the console's route guard checks policies against.
var consoleResources = []string{"organization", "user", "role", "audit", "group", "connection", "apikey", "secret",
	"webhook", "billing", "branding", "policy", "gdpr", "analytics"}

// policies writes the organization's ABAC policies through the ABAC service,
// then edits some so their history has versions.
func policies(w *world.World, o *world.Org) {
	if !o.Has("pro") {
		return
	}
	for _, s := range abacSpecs[o.Spec.Slug] {
		by := o.First(s.by...)
		in := abac.CreateInput{Name: s.name, Description: s.description, Effect: s.effect, ResourceType: s.resource,
			Action: s.action, Condition: json.RawMessage(s.condition), Priority: s.priority, Enabled: true}
		consoleSafe(w, o, in.Effect, in.ResourceType, in.Condition)
		p, err := w.Deps.ABAC.Service.Create(w.Ctx, o.ID, in, by.Actor())
		w.Check(err, "ABAC policy "+s.name)
		u := abac.UpdateInput{Name: p.Name, Description: p.Description, Effect: p.Effect, ResourceType: p.ResourceType,
			Action: p.Action, Condition: p.Condition, Priority: p.Priority, Enabled: p.Enabled}
		edits := s.edits
		if !s.enabled && len(edits) == 0 {
			edits = []abacEdit{{change: func(u *abac.UpdateInput) { u.Enabled = false }}}
		}
		for _, e := range edits {
			e.change(&u)
			if u.Enabled {
				consoleSafe(w, o, u.Effect, u.ResourceType, u.Condition)
			}
			_, err := w.Deps.ABAC.Service.Update(w.Ctx, p.ID, o.ID, u, by.Actor())
			w.Check(err, "edit ABAC policy "+s.name)
		}
	}
}

// consoleSafe stops the seed if an enabled deny policy would refuse the
// console's own requests, which carry no subject or context attributes: a
// tester would be locked out of the organization.
func consoleSafe(w *world.World, o *world.Org, effect, resource string, cond json.RawMessage) {
	if effect != "deny" {
		return
	}
	for _, rt := range consoleResources {
		if resource != "*" && resource != rt {
			continue
		}
		applies, err := abac.EvaluateCondition(cond, effect, abac.AttributeBag{
			"subject": abac.SubjectAttributes(o.Owner.ID.String(), o.ID), "resource": {"type": rt, "id": ""}, "context": {},
		})
		if applies || err != nil {
			w.Check(errors.New("deny policy "+string(cond)+" would refuse the console's "+rt+" requests"), "ABAC policy in "+o.Spec.Slug)
		}
	}
}

// rebac writes the organization's relationship tuples through the ReBAC
// service.
func rebac(w *world.World, o *world.Org) {
	by := o.First(guardians)
	write := func(object, relation, subject string) {
		_, err := w.Deps.ReBAC.Service.Write(w.Ctx, o.ID, object, relation, subject, by.Actor())
		w.Check(err, "relationship "+object+"#"+relation+"@"+subject)
	}
	for _, t := range relations[o.Spec.Slug] {
		switch kind, name, _ := strings.Cut(t[2], ":"); {
		case kind == "team":
			for _, p := range o.Active() {
				if p.Team == name {
					write(t[0], t[1], "user:"+p.ID.String())
				}
			}
		case kind == "user" && strings.Contains(name, "@"):
			write(t[0], t[1], "user:"+o.First(email(name)).ID.String())
		default:
			write(t[0], t[1], t[2])
		}
	}
}

// rateLimits saves the organization's rate-limit overrides as the console's
// form does.
func rateLimits(w *world.World, o *world.Org) {
	for _, c := range limitChanges[o.Spec.Slug] {
		body := map[string]any{}
		for _, l := range c.limits {
			body[l.key] = map[string]any{"rate": l.rate, "capacity": l.capacity}
		}
		w.API.Do(o, o.First(c.by...), "PUT", "/organizations/"+o.ID.String()+"/rate-limits", body, nil)
	}
}

// authHooks creates the organization's post-login hooks through the auth hook
// service, then changes them as their story goes.
func authHooks(w *world.World, o *world.Org) {
	for _, s := range hookSpecs[o.Spec.Slug] {
		by := o.First(s.by...)
		h, err := w.Deps.AuthHook.Service.Create(w.Ctx, o.ID, s.url, "whsec_"+w.Token(world.Alnum, 32), s.failOpen, by.Actor())
		w.Check(err, "auth hook "+s.url)
		if c := s.change; c != nil {
			_, _, err := w.Deps.AuthHook.Service.Update(w.Ctx, h.ID, o.ID, authhook.HookSettings{Enabled: &c.enabled, FailOpen: &c.failOpen}, by.Actor())
			w.Check(err, "change auth hook "+s.url)
		}
	}
}

// logSinks creates the organization's log streams through the SIEM service.
func logSinks(w *world.World, o *world.Org) {
	for _, s := range sinkSpecs[o.Spec.Slug] {
		by := o.First(s.by...)
		sk, err := w.Deps.SIEM.Service.Create(w.Ctx, o.ID, s.typ, s.endpoint, s.token(w), by.Actor())
		w.Check(err, "log sink "+s.endpoint)
		if s.disabled {
			w.Check(w.Deps.SIEM.Service.SetEnabled(w.Ctx, sk.ID, o.ID, false, by.Actor()), "disable log sink "+s.endpoint)
		}
	}
}

// webhooks creates the organization's webhook subscriptions in the console,
// then rotates or disables some.
func webhooks(w *world.World, o *world.Org) {
	if !o.Spec.Features.Webhooks || !o.Has("starter") {
		return
	}
	for _, s := range subSpecs[o.Spec.Slug] {
		by := o.First(s.by...)
		var sub struct {
			ID uuid.UUID `json:"id"`
		}
		w.API.Do(o, by, "POST", "/webhooks", map[string]any{"url": s.url, "events": s.events}, &sub)
		if s.rotated {
			w.API.Do(o, by, "POST", "/organizations/"+o.ID.String()+"/webhooks/"+sub.ID.String()+"/rotate-secret", nil, nil)
		}
		if s.state == "disabled" {
			w.API.Do(o, by, "DELETE", "/webhooks/"+sub.ID.String(), nil, nil)
		}
	}
}
