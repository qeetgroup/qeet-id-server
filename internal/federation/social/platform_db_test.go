//go:build integration

package social

import (
	"errors"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
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
		return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email)
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

// TestASignInCodeWorksOnlyInTheFlowThatIssuedIt checks that the one table of
// sign-in codes keeps the flows apart: an organisation's social sign-in code
// is not a console sign-in code, nor the other way round, and a code refused
// by the wrong exchange is still good for its own.
func TestASignInCodeWorksOnlyInTheFlowThatIssuedIt(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := newSocialFixture(t).svc
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	organisation, console := dbtest.Unique("organisation-code"), dbtest.Unique("console-code")
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'google', 'id', '\x00', '\x00')`, []any{tenant}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, tenant_id, provider, expires_at) VALUES ($1, 'social', $2, $3, 'google', NOW() + INTERVAL '5 minutes')`,
			[]any{codes.Hash(organisation), person.ID, tenant}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, expires_at) VALUES ($1, 'platform_social', $2, NOW() + INTERVAL '5 minutes')`,
			[]any{codes.Hash(console), person.ID}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}

	if _, err := svc.ExchangePlatformLogin(ctx, organisation, "192.0.2.10", "test"); !errors.Is(err, errs.ErrSocialLoginCodeInvalid) {
		t.Errorf("an organisation's sign-in code at the console exchange: %v, want %v", err, errs.ErrSocialLoginCodeInvalid)
	}
	if _, err := svc.ExchangeLogin(ctx, console, "192.0.2.10", "test"); !errors.Is(err, errs.ErrSocialLoginCodeInvalid) {
		t.Errorf("a console sign-in code at the organisation exchange: %v, want %v", err, errs.ErrSocialLoginCodeInvalid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1 AND used_at IS NULL`, person.ID); n != 2 {
		t.Fatalf("%d of the two codes unused after the wrong exchanges, want both", n)
	}

	in, err := svc.ExchangeLogin(ctx, organisation, "192.0.2.10", "test")
	if err != nil || in.Pair == nil || in.Pair.TenantID == nil || *in.Pair.TenantID != tenant {
		t.Errorf("the organisation's code at its own exchange: %+v, %v, want a session in the organisation", in, err)
	}
	out, err := svc.ExchangePlatformLogin(ctx, console, "192.0.2.10", "test")
	if err != nil || out.Pair == nil || out.Pair.TenantID != nil {
		t.Errorf("the console code at its own exchange: %+v, %v, want a session in no organisation", out, err)
	}
}
