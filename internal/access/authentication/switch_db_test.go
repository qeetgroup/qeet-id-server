//go:build integration

package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSwitchAppliesTheTargetsRules checks that a switch from one organization,
// a request scoped to it by row-level security, still applies the target
// organization's second-factor rule, and enters one without such a rule.
func TestSwitchAppliesTheTargetsRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetMFA(&poolFactors{pool: pool})
	a, home := member(t)
	strict, open := dbtest.Organization(t), dbtest.Organization(t)
	for _, organization := range []uuid.UUID{strict, open} {
		dbtest.Assign(t, a.ID, organization, dbtest.Role(t, organization))
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 0, NOW())
	`, strict); err != nil {
		t.Fatalf("require a second factor: %v", err)
	}
	pair := signIn(t, svc, a)
	p := dbtest.Principal(a.ID, home)
	p.SessionID = &pair.SessionID
	h := dbtest.Serve(p, (&Handler{Service: svc, Validate: validator.New(validator.WithRequiredStructEnabled())}).MountAuthed)
	switchTo := func(organization uuid.UUID) (int, string) {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodPost, "/auth/switch-tenant", map[string]string{"tenant_id": organization.String()})
		var body struct {
			OrganizationID uuid.UUID `json:"tenant_id"`
			Error          struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &body)
		if rec.Code == http.StatusOK && body.OrganizationID != organization {
			t.Errorf("switched into %s, want %s", body.OrganizationID, organization)
		}
		return rec.Code, body.Error.Code
	}

	if status, code := switchTo(strict); status != http.StatusForbidden || code != errs.CodeMFAEnrollmentRequired {
		t.Errorf("switch into an organisation requiring a second factor, with none: %d %q, want 403 %q", status, code, errs.CodeMFAEnrollmentRequired)
	}
	if status, code := switchTo(open); status != http.StatusOK {
		t.Errorf("switch into an organisation with no such rule: %d %q, want 200", status, code)
	}
}

// TestOwnOrganizationNeedsNoRole checks that an account signs in to its own
// organization and switches back into it holding no role there, while a guest
// whose roles were removed, or a suspended account, can't switch in.
func TestOwnOrganizationNeedsNoRole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	home, guestOf := dbtest.Organization(t), dbtest.Organization(t)
	a := dbtest.User(t, home, guestOf)
	dbtest.SetPassword(t, a.ID, testPassword)
	switchTo := func(from *TokenPair, organization uuid.UUID) (*TokenPair, error) {
		return svc.SwitchOrganization(ctx, SwitchOrganizationInput{UserID: a.ID, FromSessionID: from.SessionID, OrganizationID: organization})
	}

	signedIn := signIn(t, svc, a)
	if signedIn.OrganizationID == nil || *signedIn.OrganizationID != home {
		t.Fatalf("signed in to %v, want their own organisation %s", signedIn.OrganizationID, home)
	}
	there, err := switchTo(signedIn, guestOf)
	if err != nil {
		t.Fatalf("switch into the organisation they hold a role in: %v", err)
	}
	back, err := switchTo(there, home)
	if err != nil || back.OrganizationID == nil || *back.OrganizationID != home {
		t.Fatalf("switch back into their own organisation: %+v, %v", back, err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, a.ID, guestOf); err != nil {
		t.Fatal(err)
	}
	if next, err := switchTo(back, guestOf); !errors.Is(err, errs.ErrAuthNotOrganizationMember) || next != nil {
		t.Errorf("switch into an organisation whose roles were removed: %+v, %v; want %v", next, err, errs.ErrAuthNotOrganizationMember)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if next, err := switchTo(back, home); !errors.Is(err, errs.ErrAuthNotOrganizationMember) || next != nil {
		t.Errorf("a suspended account switching into its own organisation: %+v, %v; want %v", next, err, errs.ErrAuthNotOrganizationMember)
	}
}

// TestOpenedSessionsContinueTheirSignIn checks that a session opened by
// switching to, joining or creating an organization keeps the sign-in it came
// from: when it happened and when it ends, so none lengthens a sign-in or
// makes it look recent.
func TestOpenedSessionsContinueTheirSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	a, home := member(t)
	other, invited, created := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
	for _, organization := range []uuid.UUID{other, invited, created} {
		dbtest.Assign(t, a.ID, organization, dbtest.Role(t, organization))
	}
	from := signIn(t, svc, a)
	if _, err := pool.Exec(ctx, `
		UPDATE auth.sessions SET signed_in_at = NOW() - INTERVAL '3 hours', expires_at = NOW() + INTERVAL '1 hour' WHERE id = $1
	`, from.SessionID); err != nil {
		t.Fatal(err)
	}
	continues := func(name string, pair *TokenPair, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n := dbtest.Count(t, `
			SELECT count(*) FROM auth.sessions s JOIN auth.sessions f ON f.id = $2
			WHERE s.id = $1 AND s.signed_in_at = f.signed_in_at AND s.expires_at <= f.expires_at
		`, pair.SessionID, from.SessionID); n != 1 {
			t.Errorf("%s: the session doesn't continue the sign-in it came from", name)
		}
	}

	joined, err := svc.EnterInvitedOrganization(ctx, a.ID, invited, from.SessionID, "192.0.2.1", "test")
	continues("joining an organisation", joined, err)
	founded, err := svc.EnterCreatedOrganization(ctx, a.ID, created, from.SessionID, "192.0.2.1", "test")
	continues("creating an organisation", founded, err)
	switched, err := svc.SwitchOrganization(ctx, SwitchOrganizationInput{UserID: a.ID, FromSessionID: from.SessionID, OrganizationID: other})
	continues("switching organisation", switched, err)
	if *switched.OrganizationID == home {
		t.Errorf("switched into the home organisation, want %s", other)
	}
}

// TestCapturedAddressCannotSwitchIntoItsOrganization checks that once an
// organization requires single sign-on on a member's domain, no session of
// theirs is switched into it, as its identity provider signs them in there,
// while a session they hold still switches into an organization where they
// are a guest.
func TestCapturedAddressCannotSwitchIntoItsOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	home, guestOf := dbtest.Organization(t), dbtest.Organization(t)
	domain := dbtest.Domain(t, home)
	a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, home, guestOf)
	dbtest.SetPassword(t, a.ID, testPassword)
	switchTo := func(from *TokenPair, organization uuid.UUID) (*TokenPair, error) {
		return svc.SwitchOrganization(ctx, SwitchOrganizationInput{UserID: a.ID, FromSessionID: from.SessionID, OrganizationID: organization})
	}
	signedIn := signIn(t, svc, a)

	if _, err := pool.Exec(ctx, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, home); err != nil {
		t.Fatal(err)
	}
	svc.SetDomainCapture(captureDomain(domain))
	there, err := switchTo(signedIn, guestOf)
	if err != nil {
		t.Fatalf("switch into an organisation they are a guest of: %v", err)
	}
	if back, err := switchTo(there, home); !errors.Is(err, errs.ErrAuthSSORequired) || back != nil {
		t.Errorf("switch into the organisation that captures their address: %+v, %v; want %v", back, err, errs.ErrAuthSSORequired)
	}
}
