// Package connections seeds how each organisation connects to other systems:
// OIDC applications and their grants, SAML and OpenID Connect identity
// providers with their group mappings and break-glass members, SAML service
// providers and who is assigned to them, LDAP directories, SCIM provisioning
// and directory sync, social providers, linked identities and enterprise-setup
// links.
package connections

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Seed connects every organisation's identity providers and applications.
func Seed(w *world.World) {
	f := &fed{w: w, alertFired: map[uuid.UUID]time.Time{}, portalUses: map[uuid.UUID]portalUse{}, setups: map[uuid.UUID]setup{}}
	for _, o := range w.Orgs {
		f.social(o)
		f.sso(o)
		f.oidcConnection(o)
		f.directories(o)
		f.serviceProviders(o)
		f.applications(o)
		f.portal(o)
	}
	f.notes()
}

// fed is the step's state: what later parts and the summary need.
type fed struct {
	w *world.World
	// hosted are the applications a tester signs in to, one per organisation.
	hosted []hostedApp
	// device is the application the device-flow test uses.
	device *hostedApp
	// scim are the SCIM bearer tokens minted, by organisation name.
	scim []scimNote
	// portalURL is the active enterprise-setup link and whose it is.
	portalURL, portalOrg string
	// locked describes the application left locked out, for the summary.
	locked string
	// alertFired is when each organisation's first directory alert last fired.
	alertFired map[uuid.UUID]time.Time
	// portalUses are enterprise-setup links an identity provider's
	// administrator used, by organisation.
	portalUses map[uuid.UUID]portalUse
	// setups are each organisation's set-up times, decided once.
	setups map[uuid.UUID]setup
}

// portalUse is when an enterprise-setup link was used, and who made it.
type portalUse struct {
	by *world.Person
	at time.Time
}

// hostedApp is an application with a fixed client_id for the hosted test.
type hostedApp struct {
	org      *world.Org
	name     string
	clientID string
	secret   string // "" for a public client
	redirect string
	scopes   []string
	tester   *world.Person
	note     string
}

// scimNote is a SCIM endpoint a tester can call.
type scimNote struct{ org, token string }

// adminAt is who administers o at t: an IT administrator or Admin who had
// been there a week, else the owner.
func adminAt(o *world.Org, t time.Time) *world.Person {
	for _, role := range []string{world.RoleITAdmin, world.RoleAdmin} {
		for _, p := range o.People {
			if p.Role == role && p.Joined.Add(7*24*time.Hour).Before(t) && presentAt(p, t) {
				return p
			}
		}
	}
	return o.Owner
}

// presentAt reports whether p had joined and not yet left or been suspended
// at t.
func presentAt(p *world.Person, t time.Time) bool {
	if p.Joined.After(t) {
		return false
	}
	return p.Status == world.StatusActive || p.Since.After(t)
}

// around is t moved by up to half an hour either way, so story times don't
// all share the clock reading of the story's present.
func (f *fed) around(t time.Time) time.Time {
	return t.Add(time.Duration(f.w.Rand.Int64N(int64(time.Hour))) - 30*time.Minute)
}

// ago is a moment between lo and hi before the story's present.
func (f *fed) ago(lo, hi time.Duration) time.Time {
	return f.w.Now.Add(-lo - time.Duration(f.w.Rand.Int64N(int64(hi-lo))))
}

// workTime is a working-hours moment in loc between from and to, near a
// random one: moving a time into working hours can carry it past to.
func (f *fed) workTime(from, to time.Time, loc *time.Location) time.Time {
	t := f.w.WorkHours(f.w.Between(from, to), loc)
	if t.After(to) {
		t = to.Add(-time.Duration(f.w.Rand.Int64N(int64(min(2*time.Hour, to.Sub(from)) + 1))))
	}
	return later(t, from)
}

// later returns t, or not-before when t is earlier.
func later(t, notBefore time.Time) time.Time {
	if t.Before(notBefore) {
		return notBefore
	}
	return t
}

// record writes an audit row for an administrator's change, as the API's
// handler would have.
func (f *fed) record(t time.Time, o *world.Org, by *world.Person, action, resourceType string, resourceID *uuid.UUID, meta map[string]any) {
	f.w.Audit(t, f.event(o, by, action, resourceType, resourceID, meta))
}

// event is the audit row of by's change, by nil meaning the platform itself.
func (f *fed) event(o *world.Org, by *world.Person, action, resourceType string, resourceID *uuid.UUID, meta map[string]any) audit.Event {
	e := audit.Event{TenantID: &o.ID, Action: action, ResourceType: resourceType, ResourceID: resourceID,
		RequestID: f.requestID(), Metadata: meta}
	if by != nil {
		id := by.ID
		e.ActorUserID, e.ActorType, e.IP, e.UserAgent = &id, "user", by.Device.IP, by.Device.UserAgent
	} else {
		e.ActorType = "system"
	}
	return e
}

// requestID is an ID in the shape the API's request-ID middleware gives:
// host, a random prefix and a counter.
func (f *fed) requestID() string {
	return fmt.Sprintf("qeet-id-api-7c9d6f5b8-%s/%s-%06d", f.token(lowerDigits, 5), f.token(alnum, 10), 1+f.w.Rand.IntN(999999))
}

const (
	alnum       = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerDigits = "0123456789abcdefghijklmnopqrstuvwxyz"
	digits      = "0123456789"
)

// token is n characters drawn from alphabet.
func (f *fed) token(alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[f.w.Rand.IntN(len(alphabet))])
	}
	return b.String()
}

// uuid is a version-4 UUID drawn from the seed's random source.
func (f *fed) uuid() uuid.UUID {
	var b [16]byte
	for i := range b {
		b[i] = byte(f.w.Rand.IntN(256))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return uuid.UUID(b)
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

// apiBase is the API's public origin, as printed for testers.
func (f *fed) apiBase() string {
	if f.w.Cfg.PublicBaseURL != "" {
		return strings.TrimRight(f.w.Cfg.PublicBaseURL, "/")
	}
	return "http://localhost:" + f.w.Cfg.HTTPPort
}
