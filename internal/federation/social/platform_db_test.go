//go:build integration

package social

import (
	"errors"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSignupRefusedOnADomainAnOrganisationManages checks that signing up for
// the console with a platform provider creates no account on a domain an
// organisation has verified, or below it, while an address on no managed
// domain still gets one.
func TestSignupRefusedOnADomainAnOrganisationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	domain := dbtest.Domain(t, dbtest.Tenant(t))
	accounts := func(email string) int {
		return dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, email)
	}

	for _, host := range []string{domain, "eu." + domain} {
		email := dbtest.Unique("x") + "@" + host
		if _, err := svc.findOrCreatePlatformUser(ctx, claims(email), true); !errors.Is(err, errs.ErrUserDomainManaged) || accounts(email) != 0 {
			t.Errorf("console sign-up at %s: %v, %d accounts; want %v and none", host, err, accounts(email), errs.ErrUserDomainManaged)
		}
	}
	free := dbtest.Unique("free") + "@example.test"
	if id, err := svc.findOrCreatePlatformUser(ctx, claims(free), true); err != nil || id == uuid.Nil || accounts(free) != 1 {
		t.Errorf("console sign-up on no managed domain: %v; want an account", err)
	} else if !proved(t, id) {
		t.Error("the console sign-up stored the address the platform provider verified as unverified")
	}
}

// TestPlatformSocialSignInRefusedOnACapturedDomain checks that the console's
// own social sign-in doesn't sign in a member of an organisation that requires
// single sign-on on their domain, whether their identity is linked already or
// would be adopted by address, and links nothing new; a break-glass member
// still signs in.
func TestPlatformSocialSignInRefusedOnACapturedDomain(t *testing.T) {
	f := newSocialFixture(t)
	capturing(t, f)
	f.svc.SetPlatformProvider("console", "qeet", "idp-client-secret", f.idp.URL+"/.well-known/openid-configuration")
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	member := func() (dbtest.Account, userInfo) {
		a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, tenant, tenant)
		return a, verified(t, a)
	}
	signIn := func(person userInfo) url.Values {
		_, q := redirectQuery(t, f.signIn(t, "console", "/social/console/start", person))
		return q
	}
	_, linkedAs := member()
	if q := signIn(linkedAs); q.Get("social_code") == "" {
		t.Fatalf("console sign-in before the organisation requires single sign-on: %v; want a code", q)
	}
	exempt, exemptAs := member()
	breakGlass(t, tenant, exempt)
	adopted, adoptedAs := member()

	requireSSO(t, tenant)
	if q := signIn(linkedAs); q.Get("social_code") != "" {
		t.Errorf("a linked member's console sign-in on a captured domain: %v; want no code", q)
	}
	if q := signIn(adoptedAs); q.Get("social_code") != "" {
		t.Errorf("adopting a member on a captured domain: %v; want no code", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.platform_social_identities WHERE user_id = $1`, adopted.ID); n != 0 {
		t.Errorf("%d console identities linked to a member on a captured domain, want none", n)
	}
	if q := signIn(exemptAs); q.Get("social_code") == "" {
		t.Errorf("a break-glass member's console sign-in: %v; want a code", q)
	}
}
