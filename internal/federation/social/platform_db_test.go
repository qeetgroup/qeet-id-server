//go:build integration

package social

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSignupRefusedOnADomainAnOrganizationManages checks that signing up for
// the console with a platform provider creates no account on a domain an
// organization has verified, or below it, while an address on no managed
// domain still gets one.
func TestSignupRefusedOnADomainAnOrganizationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	domain := dbtest.Domain(t, dbtest.Organization(t))
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
// own social sign-in doesn't sign in a member of an organization that requires
// single sign-on on their domain, whether their identity is linked already or
// would be adopted by address, and links nothing new; a break-glass member
// still signs in.
func TestPlatformSocialSignInRefusedOnACapturedDomain(t *testing.T) {
	f := newSocialFixture(t)
	capturing(t, f)
	f.svc.SetPlatformProvider("console", "qeet", "idp-client-secret", f.idp.URL+"/.well-known/openid-configuration")
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	member := func() (dbtest.Account, userInfo) {
		a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
		return a, verified(t, a)
	}
	signIn := func(person userInfo) url.Values {
		_, q := redirectQuery(t, f.signIn(t, "console", "/social/console/start", person))
		return q
	}
	_, linkedAs := member()
	if q := signIn(linkedAs); q.Get("social_code") == "" {
		t.Fatalf("console sign-in before the organization requires single sign-on: %v; want a code", q)
	}
	exempt, exemptAs := member()
	breakGlass(t, organization, exempt)
	adopted, adoptedAs := member()

	requireSSO(t, organization)
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
// sign-in codes keeps the flows apart: an organization's social sign-in code
// is not a console sign-in code, nor the other way round, and a code refused
// by the wrong exchange is still good for its own.
func TestASignInCodeWorksOnlyInTheFlowThatIssuedIt(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := newSocialFixture(t).svc
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	ownCode, consoleCode := dbtest.Unique("organization-code"), dbtest.Unique("console-code")
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'google', 'id', '\x00', '\x00')`, []any{organization}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, provider, expires_at) VALUES ($1, 'social', $2, $3, 'google', NOW() + INTERVAL '5 minutes')`,
			[]any{codes.Hash(ownCode), person.ID, organization}},
		{`INSERT INTO auth.login_codes (code_hash, kind, user_id, expires_at) VALUES ($1, 'platform_social', $2, NOW() + INTERVAL '5 minutes')`,
			[]any{codes.Hash(consoleCode), person.ID}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}

	if _, err := svc.ExchangePlatformLogin(ctx, ownCode, "192.0.2.10", "test"); !errors.Is(err, ErrLoginCodeInvalid) {
		t.Errorf("an organization's sign-in code at the console exchange: %v, want %v", err, ErrLoginCodeInvalid)
	}
	if _, err := svc.ExchangeLogin(ctx, consoleCode, "192.0.2.10", "test"); !errors.Is(err, ErrLoginCodeInvalid) {
		t.Errorf("a console sign-in code at the organization exchange: %v, want %v", err, ErrLoginCodeInvalid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1 AND used_at IS NULL`, person.ID); n != 2 {
		t.Fatalf("%d of the two codes unused after the wrong exchanges, want both", n)
	}

	in, err := svc.ExchangeLogin(ctx, ownCode, "192.0.2.10", "test")
	if err != nil || in.Pair == nil || in.Pair.OrganizationID == nil || *in.Pair.OrganizationID != organization {
		t.Errorf("the organization's code at its own exchange: %+v, %v, want a session in the organization", in, err)
	}
	out, err := svc.ExchangePlatformLogin(ctx, consoleCode, "192.0.2.10", "test")
	if err != nil || out.Pair == nil || out.Pair.OrganizationID != nil {
		t.Errorf("the console code at its own exchange: %+v, %v, want a session in no organization", out, err)
	}
}

// TestPlatformSocialSignIn checks the console's own sign-in: sign-up creates
// an account only when asked to, sign-in needs one, and a signed-in person can
// link the provider to their account, which only they can complete and unlink.
func TestPlatformSocialSignIn(t *testing.T) {
	f := newSocialFixture(t)
	f.svc.SetPlatformProvider("google", "qeet", "idp-client-secret", f.idp.URL+"/.well-known/openid-configuration")
	if names := f.svc.PlatformProviderNames(); len(names) != 1 || names[0] != "google" {
		t.Errorf("platform providers %v", names)
	}
	newcomer := userInfo{Subject: "g-" + uuid.NewString(), Email: dbtest.Unique("g") + "@example.test", EmailVerified: true, Name: "Ravi"}

	if target, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start", newcomer)); target != "https://console.example.test/sign-in" || q.Get("social_error") != "no_account" {
		t.Errorf("sign in without an account: %s %v, want no_account", target, q)
	}
	target, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start?intent=signup", newcomer))
	if target != "https://console.example.test/sign-in" || q.Get("social_code") == "" {
		t.Fatalf("sign up: %s %v", target, q)
	}
	rec := browse(t, f.public, http.MethodPost, "/social/exchange", nil, map[string]string{"code": q.Get("social_code")})
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, newcomer.Email); n != 1 {
		t.Errorf("%d accounts for the newcomer, want 1", n)
	}
	if _, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start", newcomer)); q.Get("social_code") == "" {
		t.Errorf("sign in again: %v", q)
	}

	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	asA := dbtest.Serve(dbtest.Principal(a.ID, organization), f.mount)
	link := func(code string) string {
		t.Helper()
		rec := dbtest.Do(t, asA, http.MethodPost, "/social/google/link/start", nil)
		var started struct {
			AuthorizeURL string `json:"authorize_url"`
		}
		dbtest.Decode(t, rec, &started)
		f.idp.expect(t, started.AuthorizeURL, code, userInfo{Subject: "g-" + a.ID.String(), Email: a.Email, EmailVerified: true})
		target, q := redirectQuery(t, browse(t, f.public, http.MethodGet, "/social/google/callback?state="+url.QueryEscape(stateOf(started.AuthorizeURL))+"&code="+code, nil, nil))
		if target != "https://console.example.test/account/security" || q.Get("link_code") == "" {
			t.Fatalf("link callback: %s %v", target, q)
		}
		return q.Get("link_code")
	}
	b := dbtest.User(t, organization, organization)
	stolen := link("link-1")
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(b.ID, organization), f.mount), http.MethodPost, "/social/link/complete", map[string]string{"code": stolen}); !strings.Contains(rec.Body.String(), CodeLinkAccountMismatch) {
		t.Errorf("another account completing the link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asA, http.MethodPost, "/social/link/complete", map[string]string{"code": stolen}); !strings.Contains(rec.Body.String(), CodeLinkCodeInvalid) {
		t.Errorf("a link code another account tried: %d %s, want spent", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asA, http.MethodPost, "/social/link/complete", map[string]string{"code": link("link-2")}); rec.Code != http.StatusOK {
		t.Fatalf("complete the link: %d %s", rec.Code, rec.Body.String())
	}
	var mine struct {
		Items []ExternalIdentity `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asA, http.MethodGet, "/me/social/identities", nil), &mine)
	if len(mine.Items) != 1 || mine.Items[0].Provider != "google" {
		t.Fatalf("my identities %+v; want google", mine.Items)
	}
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(b.ID, organization), f.mount), http.MethodDelete, "/me/social/identities/"+mine.Items[0].ID.String(), nil); rec.Code == http.StatusNoContent {
		t.Error("another account unlinked my identity")
	}
	if rec := dbtest.Do(t, asA, http.MethodDelete, "/me/social/identities/"+mine.Items[0].ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("unlink mine: %d %s", rec.Code, rec.Body.String())
	}
	if rec := browse(t, f.public, http.MethodGet, "/social/platform/providers", nil, nil); !strings.Contains(rec.Body.String(), "google") {
		t.Errorf("platform providers: %s", rec.Body.String())
	}
}
