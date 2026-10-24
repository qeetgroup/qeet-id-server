package connections

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
)

// discovery is each tenant social provider's OpenID discovery document. GitHub
// has none, so it is never a tenant provider.
var discovery = map[string]string{
	"google":    "https://accounts.google.com/.well-known/openid-configuration",
	"microsoft": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
}

// social adds the organisation's social sign-in providers, with client IDs in
// each vendor's format, and links the accounts of people who signed in with
// them.
func (f *fed) social(o *world.Org) {
	w := f.w
	for i, name := range o.Spec.Features.Social {
		at := w.WorkHours(o.Spec.Since.Add(time.Duration(1+i*12)*24*time.Hour), o.Loc)
		if o.Spec.Since.After(w.Days(14)) {
			at = o.Spec.Since.Add(time.Duration(2+i)*time.Hour + time.Duration(w.Rand.IntN(3600))*time.Second)
		}
		by := adminAt(o, at)
		clientID, secret := f.socialClient(name)
		w.At(at, func() {
			_, err := w.Deps.Social.Service.UpsertProvider(w.Ctx, social.CreateProviderInput{
				TenantID: o.ID, Provider: name, ClientID: clientID, ClientSecret: secret, DiscoveryURL: discovery[name],
				ChangedBy: social.ChangedBy{UserID: &by.ID, ActorType: "user", IP: by.Device.IP,
					UserAgent: by.Device.UserAgent, RequestID: f.requestID()},
			})
			w.Check(err, "social provider "+name+" for "+o.Spec.Slug)
		})
		f.linkSocial(o, name, at)
	}
}

// socialClient is a client ID and secret in the provider's own format.
func (f *fed) socialClient(provider string) (id, secret string) {
	switch provider {
	case "google":
		return f.token(digits, 12) + "-" + f.token("0123456789abcdefghijklmnopqrstuvwxyz", 32) + ".apps.googleusercontent.com",
			"GOCSPX-" + f.token(alnum+"-_", 28)
	default:
		return f.uuid().String(), f.token(alnum, 3) + "8Q~" + f.token(alnum+"-_.~", 34)
	}
}

// linkSocial links accounts of people who signed in with provider since it was
// added: about a third with Google, fewer with Microsoft.
func (f *fed) linkSocial(o *world.Org, provider string, since time.Time) {
	w := f.w
	share := 0.35
	if provider == "microsoft" {
		share = 0.12
	}
	if len(o.People) <= 3 {
		share = 0.7
	}
	batch := &pgx.Batch{}
	for _, p := range o.Active() {
		if p.Unverified || !w.Chance(share) {
			continue
		}
		from := later(p.Joined.Add(time.Hour), since.Add(time.Hour))
		if !from.Before(w.Now.Add(-2 * time.Hour)) {
			continue
		}
		linked := f.workTime(from, w.Now.Add(-2*time.Hour), p.Loc)
		subject, meta := f.socialSubject(provider, o)
		batch.Queue(`INSERT INTO "user".external_identities (id, user_id, tenant_id, provider, subject, email, metadata, linked_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.New(), p.ID, o.ID, provider, subject, p.Email, meta, linked)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "link "+provider+" identities in "+o.Spec.Slug)
}

// socialSubject is the provider's subject for an account: Google's numeric
// sub, Microsoft's pairwise one.
func (f *fed) socialSubject(provider string, o *world.Org) (string, map[string]any) {
	if provider == "google" {
		return "1" + f.token(digits, 20), map[string]any{"hd": o.Spec.Domain, "email_verified": true}
	}
	return "AAAAAAAAAAAAAAAAAAAAA" + f.token(alnum+"-_", 22), map[string]any{"tid": "9188040d-6c67-4c5b-b112-36a304b66dad"}
}
