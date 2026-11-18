//go:build integration

package invite

import (
	"net/http"
	"slices"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestInviteAccept checks that accepting an invitation creates the account in
// the inviting organization with the invited role, signs it in there, and spends the
// invitation.
func TestInviteAccept(t *testing.T) {
	ctx := dbtest.Context(t)
	h, authSvc := newHandler(t)
	organization := dbtest.Organization(t)
	role := dbtest.Role(t, organization)
	email := dbtest.Unique("invitee") + "@example.test"
	inv, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: email, RoleID: &role}, audit.Actor{})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	public := dbtest.Serve(nil, h.MountPublic)
	rec := dbtest.Do(t, public, http.MethodPost, "/invites/accept", map[string]any{"token": token, "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept: status %d (%s)", rec.Code, rec.Body.String())
	}
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if pair.AccessToken == "" || pair.OrganizationID == nil || *pair.OrganizationID != organization {
		t.Fatalf("accept signed in to organization %v, want %s", pair.OrganizationID, organization)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM account.users u JOIN rbac.user_roles ur ON ur.user_id = u.id
		WHERE u.id = $1 AND u.organization_id = $2 AND u.email = $3 AND ur.organization_id = $2 AND ur.role_id = $4
	`, pair.UserID, organization, email, role); n != 1 {
		t.Error("the accepted account is not a member of the inviting organization with the invited role")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.invites WHERE id = $1 AND status = 'accepted'`, inv.ID); n != 1 {
		t.Error("the invitation was not marked accepted")
	}

	if rec := dbtest.Do(t, public, http.MethodPost, "/invites/accept", map[string]any{"token": token, "password": testPassword}); rec.Code != http.StatusBadRequest {
		t.Errorf("second accept: status %d, want 400", rec.Code)
	}
	login, err := authSvc.Login(ctx, auth.LoginInput{Email: email, Password: testPassword})
	if err != nil || login.Pair == nil {
		t.Fatalf("sign in with the invitation's password: %+v, %v", login, err)
	}
}

// TestInviteAcceptWithOneConnection checks that an invitation is accepted with
// only one connection free, while the organization's sign-in methods and
// password rules are read from the database.
func TestInviteAcceptWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	h.Service.methods = policies(t)
	organization := dbtest.Organization(t)
	_, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test"}, audit.Actor{})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	if res, err := h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{}); err != nil || res.OrganizationID != organization {
		t.Fatalf("accept: %+v, %v; want an account in %s", res, err, organization)
	}
}

// TestAcceptAnotherOrganizationsInvitation checks that a member of one
// organization, signed in to it and so scoped to it by row-level security,
// sees and accepts an invitation from another and joins it with its role.
func TestAcceptAnotherOrganizationsInvitation(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	home, other := dbtest.Organization(t), dbtest.Organization(t)
	a := dbtest.User(t, home, home)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	role := dbtest.Role(t, other)
	inv, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: other, Email: a.Email, RoleID: &role}, audit.Actor{})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	asMember := dbtest.Serve(dbtest.Principal(a.ID, home), h.MountAuthed)
	if ids := dbtest.IDs(t, dbtest.Do(t, asMember, http.MethodGet, "/me/invites", nil)); !slices.Contains(ids, inv.ID) {
		t.Fatalf("my invitations %v, want the other organization's %s", ids, inv.ID)
	}
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/"+inv.ID.String()+"/accept", nil); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2 AND role_id = $3`, a.ID, other, role); n != 1 {
		t.Error("accepting didn't give the invitation's role in its organization")
	}
}
