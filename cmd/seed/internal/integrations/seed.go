// Package integrations seeds each organisation's integrations: API keys, service
// principals, AI agents, webhooks and their deliveries, auth hooks, secrets,
// token-vault connections, verifiable credentials, ABAC policies,
// relationship tuples, the access decisions they answered, rate-limit
// overrides and log streaming.
package integrations

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Seed builds every organisation's integrations in the order its people set
// them up, then the webhook traffic everything since has produced.
func Seed(w *world.World) {
	d := &dev{w: w, box: vaultCipher(w), host: "qeet-id-api-7c9f4d6b8-x2kqp/" + token(w, 10)}
	d.refuseUnknownEvent()
	for _, o := range w.Orgs {
		d.apiKeys(o)
		d.principals(o)
		d.agents(o)
		d.secrets(o)
		d.tokenVault(o)
		d.credentials(o)
		d.abac(o)
		d.rebac(o)
		d.decisions(o)
		d.rateLimits(o)
		d.authHooks(o)
		d.logSinks(o)
		d.subscriptions(o)
	}
	for _, o := range w.Orgs {
		d.deliveries(o)
	}
	d.drainOutbox()

	const s = "Developer screens (Qeet Group as saibabu@qeet.in)"
	w.Note(s, "Webhooks, Qeet Group: active (Qeet People, Qeet Notify), failing and retrying (Slack relay), disabled (warehouse),")
	w.Note(s, "  auto-disabled (staging Notify, with a bell alert). Endpoints don't resolve: live deliveries fail with \"no such host\".")
	w.Note(s, "API keys: expiring soon, expired (Rohan's CLI), revoked (leaked Statuspage key); agents active/suspended; secrets rotated.")
	w.Note(s, "ABAC versions: \"Contractors: business hours only\" (3); ReBAC: object document:readme (Qeet, Lumen, Northwind, Meridian).")
	w.Note(s, "Access decisions: a month of the products' questions (Qeet Logs, Qeet Pay, Qeet People, Qeet AI), with the policy refusals.")
	w.Note(s, "Auth hooks: enabled fail-open at Northwind and Meridian — a sign-in there records auth_hook.skipped; Qeet's are off.")
	w.Note(s, "Log streaming: Qeet HTTP (healthy), Northwind Splunk HEC (healthy) + old ArcSight (off), Meridian Datadog (403).")
}

// dev is the step's state: the cipher the token vault seals with, and a
// request counter so each simulated console request has its own id.
type dev struct {
	w    *world.World
	box  *envelope.Cipher
	host string
	seq  int
	subs map[uuid.UUID][]sub // each organisation's webhook subscriptions
}

// vaultCipher is the cipher the API's token vault seals with: the vault key
// from SECRETS_KEY (or KMS). With no key configured the API generates one at
// every start, so any key will do.
func vaultCipher(w *world.World) *envelope.Cipher {
	key := make([]byte, 32)
	if w.Cfg.SecretsKey != "" || w.Cfg.SecretsProvider == "aws-kms" {
		kp, err := bootstrap.SecretsKeyProvider(w.Ctx, w.Cfg)
		w.Check(err, "vault key provider")
		key, err = kp.DataKey(w.Ctx)
		w.Check(err, "vault data key")
	} else {
		_, err := rand.Read(key)
		w.Check(err, "throwaway vault key")
	}
	box, err := envelope.New(key)
	w.Check(err, "vault cipher")
	return box
}

// as is p acting in one console request, so the rows it writes share a
// request id.
func (d *dev) as(p *world.Person) audit.Actor {
	a := p.Actor()
	a.RequestID = d.requestID()
	return a
}

// requestID is the next request id, in the shape chi's RequestID middleware
// gives them.
func (d *dev) requestID() string {
	d.seq++
	return fmt.Sprintf("%s-%06d", d.host, d.seq)
}

// token is n random URL-safe characters from the seeded generator.
func token(w *world.World, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return chars(w, alphabet, n)
}

// chars is n random characters of alphabet.
func chars(w *world.World, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[w.Rand.IntN(len(alphabet))]
	}
	return string(b)
}

// hexToken is n random lower-case hex digits.
func hexToken(w *world.World, n int) string { return chars(w, "0123456789abcdef", n) }

// b64 is n random bytes, base64-encoded.
func b64(w *world.World, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(w.Rand.IntN(256))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// who matches a person.
type who func(*world.Person) bool

func email(e string) who { return func(p *world.Person) bool { return p.Email == e } }

func dept(name string) who { return func(p *world.Person) bool { return p.Department == name } }

func team(name string) who { return func(p *world.Person) bool { return p.Team == name } }

func title(part string) who {
	return func(p *world.Person) bool { return strings.Contains(p.Title, part) }
}

func role(names ...string) who {
	return func(p *world.Person) bool {
		for _, n := range names {
			if p.Role == n {
				return true
			}
		}
		return false
	}
}

// both matches a person matching a and b.
func both(a, b who) who { return func(p *world.Person) bool { return a(p) && b(p) } }

// builders are the roles that may manage API keys, webhooks and secrets.
var builders = role(world.RoleOwner, world.RoleAdmin, world.RoleDeveloper)

// guardians are the roles that may manage policies.
var guardians = role(world.RoleOwner, world.RoleAdmin, world.RoleSecurity, world.RoleITAdmin)

// person is o's first active member there by t who matches the first of
// prefs anyone matches — guests included — or the owner.
func person(o *world.Org, t time.Time, prefs ...who) *world.Person {
	for _, pref := range prefs {
		for _, p := range o.Active() {
			if p.ID != uuid.Nil && !p.Joined.After(t) && pref(p) {
				return p
			}
		}
		for _, g := range o.Guests {
			if g.Status == world.StatusActive && pref(g) && guestSince(o, g).Before(t) {
				return g
			}
		}
	}
	return o.Owner
}

// issuer is who creates a credential carrying scopes at t: the first preferred
// person allowed to (the API refuses a scope its creator doesn't hold), else an
// administrator who is, else the owner.
func (d *dev) issuer(o *world.Org, t time.Time, scopes []string, prefs ...who) *world.Person {
	allowed := func(p *world.Person) bool {
		caller := &httpx.Principal{UserID: &p.ID, TenantID: &o.ID, ActorType: "user"}
		return d.w.Deps.RBAC.Repo.CheckGrantScopes(d.w.Ctx, caller, o.ID, scopes) == nil
	}
	admin := func(p *world.Person) bool { return p.Role == world.RoleAdmin }
	for _, pref := range append(append([]who{}, prefs...), admin) {
		for _, p := range people(o, t, pref) {
			if allowed(p) {
				return p
			}
		}
		for _, g := range o.Guests {
			if g.Status == world.StatusActive && pref(g) && guestSince(o, g).Before(t) && allowed(g) {
				return g
			}
		}
	}
	return o.Owner
}

// people is every active member of o there by t who matches m.
func people(o *world.Org, t time.Time, m who) []*world.Person {
	var out []*world.Person
	for _, p := range o.Active() {
		if p.ID != uuid.Nil && !p.Joined.After(t) && m(p) {
			out = append(out, p)
		}
	}
	return out
}

// guestSince is when g joined o as a guest.
func guestSince(o *world.Org, g *world.Person) time.Time {
	for _, r := range g.GuestOf {
		if r.Org == o {
			return r.Since
		}
	}
	return g.Joined
}

// when is daysAgo days before now in o's working hours, but no earlier than a
// day after the organisation signed up or an hour after any of ps joined it,
// and never in the future.
func (d *dev) when(o *world.Org, daysAgo float64, ps ...*world.Person) time.Time {
	w := d.w
	t := w.Days(daysAgo)
	if daysAgo >= 1 {
		t = w.WorkHours(t, o.Loc)
	}
	floor := o.Spec.Since.Add(24 * time.Hour)
	if o.Spec.Since.After(w.Days(3)) {
		floor = o.Spec.Since.Add(2 * time.Hour)
	}
	for _, p := range ps {
		if p == nil {
			continue
		}
		joined := p.Joined
		if p.Org != o {
			joined = guestSince(o, p)
		}
		if j := joined.Add(time.Hour); j.After(floor) {
			floor = j
		}
	}
	if t.Before(floor) {
		t = floor.Add(time.Duration(w.Rand.IntN(90)) * time.Minute)
	}
	if latest := w.Now.Add(-10 * time.Minute); t.After(latest) {
		t = latest.Add(-time.Duration(w.Rand.IntN(50)) * time.Minute)
	}
	return t
}

// jitter spreads a creation date more than two months back by up to 7% either
// way, so things set up "about 200 days ago" don't all share a day.
func (d *dev) jitter(days float64) float64 {
	if days < 60 {
		return days
	}
	return days * (1 + (d.w.Rand.Float64()*2-1)*0.07)
}

// leaver is an account of o deleted since it joined, holding one of roles,
// for the credentials revoked when someone leaves; nil when there is none.
func leaver(o *world.Org, m who) *world.Person {
	for _, p := range o.People {
		if p.Status == world.StatusDeleted && p.ID != uuid.Nil && m(p) && p.Since.Sub(p.Joined) > 30*24*time.Hour {
			return p
		}
	}
	return nil
}
