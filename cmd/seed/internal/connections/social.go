package connections

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
)

// discovery is each OpenID Connect social provider's discovery document.
// GitHub, Facebook, X, Discord and Apple aren't OpenID Connect: Qeet ID calls
// each through its own adapter, so they have none.
var discovery = map[string]string{
	"google":    "https://accounts.google.com/.well-known/openid-configuration",
	"microsoft": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
}

// linkShare is the share of an organization's people who linked each provider.
var linkShare = map[string]float64{
	"google": 0.35, "microsoft": 0.12, "github": 0.3, "apple": 0.08, "discord": 0.05, "facebook": 0.15, "x": 0.1,
}

// social adds the organization's social sign-in providers, with client IDs in
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
		in := f.socialClient(o, name)
		in.OrganizationID, in.Provider, in.DiscoveryURL = o.ID, name, discovery[name]
		in.ChangedBy = social.ChangedBy{UserID: &by.ID, ActorType: "user", IP: by.Device.IP,
			UserAgent: by.Device.UserAgent, RequestID: f.requestID()}
		w.At(at, func() {
			_, err := w.Deps.Social.Service.UpsertProvider(w.Ctx, in)
			w.Check(err, "social provider "+name+" for "+o.Spec.Slug)
		})
		f.linkSocial(o, name, at)
	}
}

// socialClient is a client ID and secret in the provider's own format: for
// Apple, a Services ID, team and key IDs and a real .p8 key, which Qeet ID signs
// its client secret with.
func (f *fed) socialClient(o *world.Org, provider string) social.CreateProviderInput {
	switch provider {
	case "google":
		return social.CreateProviderInput{ClientID: f.token(digits, 12) + "-" + f.token("0123456789abcdefghijklmnopqrstuvwxyz", 32) + ".apps.googleusercontent.com",
			ClientSecret: "GOCSPX-" + f.token(alnum+"-_", 28)}
	case "github":
		return social.CreateProviderInput{ClientID: "Ov23li" + f.token(alnum, 14), ClientSecret: f.token("0123456789abcdef", 40)}
	case "facebook":
		return social.CreateProviderInput{ClientID: "1" + f.token(digits, 15), ClientSecret: f.token("0123456789abcdef", 32)}
	case "x":
		return social.CreateProviderInput{ClientID: f.token(alnum+"-_", 34), ClientSecret: f.token(alnum+"-_", 50)}
	case "discord":
		return social.CreateProviderInput{ClientID: "1" + f.token(digits, 18), ClientSecret: f.token(alnum+"-_", 32)}
	case "apple":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		f.w.Check(err, "Apple sign-in key")
		der, err := x509.MarshalPKCS8PrivateKey(key)
		f.w.Check(err, "encode Apple sign-in key")
		upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		return social.CreateProviderInput{ClientID: reverseDomain(o.Spec.Domain) + ".signin",
			ClientSecret: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
			AppleTeamID:  f.token(upper, 10), AppleKeyID: f.token(upper, 10)}
	default:
		return social.CreateProviderInput{ClientID: f.uuid().String(), ClientSecret: f.token(alnum, 3) + "8Q~" + f.token(alnum+"-_.~", 34)}
	}
}

// reverseDomain is domain in reverse-DNS order, as Apple Services IDs are.
func reverseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	slices.Reverse(parts)
	return strings.Join(parts, ".")
}

// linkSocial links accounts of people who signed in with provider since it was
// added: about a third with Google, fewer with Microsoft.
func (f *fed) linkSocial(o *world.Org, provider string, since time.Time) {
	w := f.w
	share := linkShare[provider]
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
		batch.Queue(`INSERT INTO account.external_identities (id, user_id, organization_id, provider, subject, email, metadata, linked_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.New(), p.ID, o.ID, provider, subject, p.Email, meta, linked)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "link "+provider+" identities in "+o.Spec.Slug)
}

// socialSubject is the provider's subject for an account, in its own form:
// Google's numeric sub, Microsoft's pairwise one, GitHub's, Facebook's, X's and
// Discord's numeric IDs, and Apple's team-scoped one.
func (f *fed) socialSubject(provider string, o *world.Org) (string, map[string]any) {
	switch provider {
	case "google":
		return "1" + f.token(digits, 20), map[string]any{"hd": o.Spec.Domain, "email_verified": true}
	case "github":
		return "1" + f.token(digits, 7), map[string]any{"email_verified": true}
	case "facebook":
		return "10" + f.token(digits, 15), map[string]any{}
	case "x":
		return "1" + f.token(digits, 18), map[string]any{}
	case "discord":
		return "1" + f.token(digits, 17), map[string]any{"email_verified": true}
	case "apple":
		return "00" + f.token(digits, 4) + "." + f.token("0123456789abcdef", 32) + "." + f.token(digits, 4),
			map[string]any{"email_verified": true, "is_private_email": false}
	}
	return "AAAAAAAAAAAAAAAAAAAAA" + f.token(alnum+"-_", 22), map[string]any{"tid": "9188040d-6c67-4c5b-b112-36a304b66dad"}
}
