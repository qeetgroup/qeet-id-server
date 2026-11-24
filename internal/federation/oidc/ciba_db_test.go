//go:build integration

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestBackchannelApprovalMeetsTheOrganizationsRules checks that approving a
// backchannel request needs what signing in to the application does: the
// person still a member of its organization, an address its rules allow (a
// refusal recorded), and a session that met the second factor it requires.
func TestBackchannelApprovalMeetsTheOrganizationsRules(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	authSvc := authtest.New(t, pool, func(d *authentication.Deps) { d.MFA = secondFactors(t, pool) })
	svc := newTestService(t, pool, dbtest.Issuer(t), func(d *Deps) {
		d.Addresses = ipallow.NewService(pool)
		d.SessionFactors = authSvc.SessionFactorShortfall
	})
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeCIBA}})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`WITH rule AS (INSERT INTO organization.ip_rules (organization_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO organization.ip_rules_config (organization_id, enabled) VALUES ($1, TRUE)`, organization)
	const office, elsewhere = "192.0.2.10", "198.51.100.7"
	a := dbtest.User(t, home, home, organization)
	pair, err := authSvc.IssuePair(ctx, a.ID, home, office, "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	session := pair.SessionID
	decide := func(id uuid.UUID, ip string) error {
		return svc.DecideBackchannel(ctx, a.ID, session, id, true, ip)
	}

	_, id := pendingBackchannel(t, svc, client, secret, a)
	if err := decide(id, elsewhere); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("approve from an address the rules refuse: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.address_refused' AND metadata->>'path' = 'ciba_approval'`, organization); n != 1 {
		t.Errorf("the refused approval was recorded %d times, want once", n)
	}
	if err := decide(id, office); err != nil {
		t.Fatalf("approve from the office: %v", err)
	}

	exec(`INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since) VALUES ($1, 'required', 0, NOW())`, organization)
	_, id = pendingBackchannel(t, svc, client, secret, a)
	if err := decide(id, office); !errors.Is(err, errs.ErrMFAEnrollmentRequired) {
		t.Errorf("approve through a session short of the factor the organization requires: %v, want %v", err, errs.ErrMFAEnrollmentRequired)
	}
	exec(`UPDATE auth.sessions SET second_factor = 'mfa' WHERE id = $1`, session)
	if err := decide(id, office); err != nil {
		t.Fatalf("approve through a session that met the factor: %v", err)
	}

	_, id = pendingBackchannel(t, svc, client, secret, a)
	exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, a.ID, organization)
	if err := decide(id, office); !errors.Is(err, ErrUserOrganizationMismatch) {
		t.Errorf("approve once no longer a member of the organization: %v, want %v", err, ErrUserOrganizationMismatch)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_ciba_requests WHERE id = $1 AND status = 'pending'`, id); n != 1 {
		t.Error("a refused approval changed the request")
	}
}

// TestCIBAGrantRemovedAfterAuthorizeIsRefusedAtToken checks that collecting a
// backchannel grant's tokens needs a confidential client still holding the CIBA
// grant and a person still in its organization, and that a token that fails to
// be stored leaves the request unspent, so a later poll gets it.
func TestCIBAGrantRemovedAfterAuthorizeIsRefusedAtToken(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeCIBA, "refresh_token"}})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	approved := func(a dbtest.Account) string {
		t.Helper()
		raw, id := pendingBackchannel(t, svc, client, secret, a)
		if err := svc.DecideBackchannel(ctx, a.ID, uuid.Nil, id, true, ""); err != nil {
			t.Fatalf("approve: %v", err)
		}
		return raw
	}
	// A poll at once after another is slow_down; the tests poll as if later.
	repoll := func() {
		exec(`UPDATE auth.oidc_ciba_requests SET last_polled_at = NULL WHERE client_id = $1`, client.ClientID)
	}
	a := dbtest.User(t, organization, organization)

	authReqID := approved(a)
	exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY['refresh_token'] WHERE client_id = $1`, client.ClientID)
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); !errors.Is(err, ErrGrantTypeNotAllowed) {
		t.Errorf("collect once the client lost the CIBA grant: %v, want %v", err, ErrGrantTypeNotAllowed)
	}
	exec(`UPDATE auth.oidc_clients SET grant_types = ARRAY[$2, 'refresh_token'] WHERE client_id = $1`, client.ClientID, grantTypeCIBA)
	repoll()
	exec(`UPDATE auth.oidc_clients SET type = 'public' WHERE client_id = $1`, client.ClientID)
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Error("collect once the client is no longer confidential: tokens issued")
	}
	exec(`UPDATE auth.oidc_clients SET type = 'confidential' WHERE client_id = $1`, client.ClientID)
	repoll()

	owner := dbtest.Owner(t)
	if _, err := owner.Exec(ctx, `
		CREATE FUNCTION pg_temp.refuse_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refresh store down'; END $$;
		CREATE TRIGGER refuse_refresh BEFORE INSERT ON auth.oidc_refresh_tokens FOR EACH ROW
		WHEN (NEW.client_id = '`+client.ClientID+`') EXECUTE FUNCTION pg_temp.refuse_refresh()`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Fatal("collect while the refresh token can't be stored: tokens issued")
	}
	if _, err := owner.Exec(ctx, `DROP TRIGGER refuse_refresh ON auth.oidc_refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	repoll()
	if issued, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err != nil || issued.RefreshToken == "" {
		t.Errorf("collect after the failed store: %+v, %v; want the tokens", issued, err)
	}

	authReqID = approved(a)
	exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, a.ID, organization)
	exec(`UPDATE account.users SET organization_id = $2 WHERE id = $1`, a.ID, dbtest.Organization(t))
	repoll()
	if _, err := svc.BackchannelToken(ctx, client.ClientID, secret, authReqID); err == nil {
		t.Error("collect once the person left the organization: tokens issued")
	}
}

// prompt is one out-of-band notice a Notifier was asked to deliver.
type prompt struct {
	organizationID, userID   uuid.UUID
	title, description, href string
}

// promptBox is a Notifier that keeps the prompts it is asked to deliver.
type promptBox struct {
	mu   sync.Mutex
	sent []prompt
}

// Notify records the prompt.
func (b *promptBox) Notify(_ context.Context, organizationID, userID uuid.UUID, _, title, description, href string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, prompt{organizationID: organizationID, userID: userID, title: title, description: description, href: href})
	return nil
}

// TestBackchannelFlow checks that only a confidential application with the
// CIBA grant starts a backchannel sign-in, for a person of its own
// organization, who is prompted and alone decides it, once; and that polling
// answers pending, slow_down and access_denied, and an approval buys tokens once.
func TestBackchannelFlow(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	prompts := &promptBox{}
	p := newProvider(t, func(d *Deps, _ *authentication.Service) { d.Notifier = prompts })
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	colleague := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, otherOrganization, otherOrganization)
	kiosk, secret := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Name: "Kiosk", GrantTypes: []string{grantTypeCIBA, "refresh_token"}})
	plain, plainSecret := registerClient(t, p.svc, organization)
	public, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Type: "public"})
	hint := func(email string) url.Values {
		return url.Values{"login_hint": {email}, "scope": {"openid"}, "binding_message": {"Till 4"}}
	}
	start := func(user, pass string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, p.public, "/oauth/bc-authorize", form, user, pass)
	}

	for _, tc := range []struct {
		name, user, pass string
		form             url.Values
		want             string
	}{
		{"a public client", public.ClientID, "", hint(person.Email), errs.CodeOIDCClientAuthFailed},
		{"an application without the grant", plain.ClientID, plainSecret, hint(person.Email), "unauthorized_client"},
		{"a wrong secret", kiosk.ClientID, "wrong-secret", hint(person.Email), errs.CodeOIDCClientAuthFailed},
		{"a person of another organization", kiosk.ClientID, secret, hint(outsider.Email), "unknown_user_id"},
		{"no login_hint", kiosk.ClientID, secret, url.Values{"scope": {"openid"}}, "invalid_request"},
		{"a scope the application may not have", kiosk.ClientID, secret, url.Values{"login_hint": {person.Email}, "scope": {"admin"}}, "invalid_scope"},
		{"a resource", kiosk.ClientID, secret, url.Values{"login_hint": {person.Email}, "resource": {resourceA}}, "invalid_target"},
	} {
		if rec := start(tc.user, tc.pass, tc.form); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("start with %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_ciba_requests WHERE organization_id = $1`, organization); n != 0 || len(prompts.sent) != 0 {
		t.Errorf("refused requests stored %d and prompted %d, want none", n, len(prompts.sent))
	}

	begin := func() string {
		t.Helper()
		rec := start(kiosk.ClientID, secret, hint(strings.ToUpper(person.Email)))
		var out CIBAAuthResponse
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusOK || out.AuthReqID == "" || out.Interval != cibaPollInterval {
			t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
		}
		return out.AuthReqID
	}
	collect := func(authReqID string) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, p.public, "/oauth/token", url.Values{"grant_type": {grantTypeCIBA}, "auth_req_id": {authReqID}}, kiosk.ClientID, secret)
	}
	// poll collects as a client that waited out the interval since its last poll.
	poll := func(authReqID string) *httptest.ResponseRecorder {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE auth.oidc_ciba_requests SET last_polled_at = last_polled_at - INTERVAL '1 minute'
			WHERE organization_id = $1 AND auth_req_id_hash = $2`, organization, codes.Hash(authReqID)); err != nil {
			t.Fatal(err)
		}
		return collect(authReqID)
	}
	pollError := func(authReqID string) string {
		t.Helper()
		code, _ := decodeTokenError(t, poll(authReqID))
		return code
	}
	asPerson := dbtest.Serve(dbtest.Principal(person.ID, organization), p.mount)
	asColleague := dbtest.Serve(dbtest.Principal(colleague.ID, organization), p.mount)
	pending := func(h http.Handler) []CIBAPendingRequest {
		t.Helper()
		var page struct {
			Items []CIBAPendingRequest `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/oauth/bc-authorize/pending", nil), &page)
		return page.Items
	}
	decide := func(h http.Handler, id uuid.UUID, approve bool) *httptest.ResponseRecorder {
		t.Helper()
		return dbtest.Do(t, h, http.MethodPost, "/oauth/bc-authorize/decision", map[string]any{"id": id, "approve": approve})
	}

	authReqID := begin()
	if len(prompts.sent) != 1 || prompts.sent[0].userID != person.ID || prompts.sent[0].organizationID != organization || prompts.sent[0].description != "Till 4" || prompts.sent[0].href != "" {
		t.Errorf("prompts %+v, want one to the person in the organization with the binding message, linking to no page", prompts.sent)
	}
	if got := pollError(authReqID); got != "authorization_pending" {
		t.Errorf("poll before approval: %s, want authorization_pending", got)
	}
	if got, _ := decodeTokenError(t, collect(authReqID)); got != "slow_down" {
		t.Errorf("poll again at once: %s, want slow_down", got)
	}
	if got := pending(asColleague); len(got) != 0 {
		t.Errorf("a colleague sees the person's requests: %+v", got)
	}
	mine := pending(asPerson)
	if len(mine) != 1 || mine[0].ClientName != "Kiosk" || mine[0].BindingMessage == nil || *mine[0].BindingMessage != "Till 4" {
		t.Fatalf("the person's pending requests %+v, want the kiosk's with its binding message", mine)
	}
	if rec := decide(asColleague, mine[0].ID, true); !strings.Contains(rec.Body.String(), CodeCIBARequestNotOwned) {
		t.Errorf("a colleague approving: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(asPerson, mine[0].ID, true); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(asPerson, mine[0].ID, false); !strings.Contains(rec.Body.String(), CodeCIBARequestAlreadyDecided) {
		t.Errorf("decide again: %d %s", rec.Code, rec.Body.String())
	}
	rec := poll(authReqID)
	var issued TokenResponse
	dbtest.Decode(t, rec, &issued)
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if rec.Code != http.StatusOK || err != nil || claims.UserID != person.ID || claims.ClientID != kiosk.ClientID || issued.IDToken == "" || issued.RefreshToken == "" {
		t.Fatalf("collect: %d %s, %v", rec.Code, rec.Body.String(), err)
	}
	if got := pollError(authReqID); got != "invalid_grant" {
		t.Errorf("collect twice: %s, want invalid_grant", got)
	}

	deniedID := begin()
	if rec := decide(asPerson, pending(asPerson)[0].ID, false); rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(deniedID); got != "access_denied" {
		t.Errorf("poll after denial: %s, want access_denied", got)
	}
}

// secondFactors is the second-factor service, reading the factors each
// account holds and the organization's requirement.
func secondFactors(t *testing.T, pool *pgxpool.Pool) *mfa.Service {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	factors, err := mfa.NewService(pool, mfa.Deps{
		Issuer: "Qeet", Sender: notifier.LogSender{}, Cipher: box, Plan: smsPlans{},
		Deliverable: func(string) bool { return true }, WebAuthn: noPasskeys{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return factors
}

// smsPlans includes SMS codes in every plan.
type smsPlans struct{}

func (smsPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// noPasskeys stands for the passkey second factor, which no test here uses.
type noPasskeys struct{ mfa.WebAuthnVerifier }
