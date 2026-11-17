//go:build integration

package invite

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPassword = "Kx7mQ2vLp9Wz"

// newHandler wires the invitation handler as bootstrap does.
func newHandler(t *testing.T) (*Handler, *auth.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	svc := NewService(pool, &dbtest.Mailbox{}, 0, "https://console.example.test")
	svc.SetPasswordRules(authpolicy.NewService(pool))
	svc.SetGrantCheck(rbac.NewRepository(pool).CheckGrantRole)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	h := &Handler{
		Service:     svc,
		AuthService: authSvc,
		Validate:    validator.New(validator.WithRequiredStructEnabled()),
		GrantCheck:  rbac.NewRepository(pool).CheckGrantRole,
	}
	return h, authSvc
}

// TestInvitesStayInTheirOrganization checks that one organization can neither list, resend
// nor revoke another organization's invitation, and that only the invited address
// can accept it.
func TestInvitesStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminB := dbtest.User(t, organizationB, organizationB)
	inviteA, tokenA, err := h.Service.Create(ctx, CreateInput{OrganizationID: organizationA, Email: dbtest.Unique("invitee") + "@example.test"}, audit.Actor{})
	if err != nil {
		t.Fatalf("invite in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), h.MountAuthed)
	path := "/invites/" + inviteA.ID.String()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, path + "/resend", http.StatusNotFound},
		{http.MethodDelete, path, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + organizationA.String() + "/invites", http.StatusForbidden},
		{http.MethodPost, "/me/invites/" + inviteA.ID.String() + "/accept", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+organizationB.String()+"/invites", nil)); slices.Contains(ids, inviteA.ID) {
		t.Error("tenant B's invitation list includes tenant A's")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM organization.invites WHERE id = $1 AND status = 'pending' AND token_hash = $2
	`, inviteA.ID, codes.Hash(tokenA)); n != 1 {
		t.Error("tenant B changed tenant A's invitation")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, adminB.ID, organizationA); n != 0 {
		t.Error("tenant B's admin joined tenant A")
	}
}

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
		t.Fatalf("accept signed in to tenant %v, want %s", pair.OrganizationID, organization)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM account.users u JOIN rbac.user_roles ur ON ur.user_id = u.id
		WHERE u.id = $1 AND u.organization_id = $2 AND u.email = $3 AND ur.organization_id = $2 AND ur.role_id = $4
	`, pair.UserID, organization, email, role); n != 1 {
		t.Error("the accepted account is not a member of the inviting tenant with the invited role")
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

// TestInviteLinkGoesOnlyToTheInvitee checks that creating and resending an
// invitation answer with the invitation but not its token, which reaches only
// the invited address.
func TestInviteLinkGoesOnlyToTheInvitee(t *testing.T) {
	h, _ := newHandler(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.MountAuthed)

	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/invites", map[string]any{"email": dbtest.Unique("invitee") + "@example.test"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d (%s)", rec.Code, rec.Body.String())
	}
	var created map[string]json.RawMessage
	dbtest.Decode(t, rec, &created)
	var inv Invite
	if err := json.Unmarshal(created["invite"], &inv); err != nil || inv.ID == uuid.Nil {
		t.Fatalf("create answered no invitation: %s", rec.Body.String())
	}
	if _, ok := created["token"]; ok {
		t.Error("create answered with the invitation's token")
	}

	rec = dbtest.Do(t, asAdmin, http.MethodPost, "/invites/"+inv.ID.String()+"/resend", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("resend: status %d (%s)", rec.Code, rec.Body.String())
	}
	var resent map[string]json.RawMessage
	dbtest.Decode(t, rec, &resent)
	if _, ok := resent["token"]; ok {
		t.Error("resend answered with the invitation's token")
	}
}

// TestInviteAcceptWithOneConnection checks that an invitation is accepted with
// only one connection free, while the organization's sign-in methods and
// password rules are read from the database.
func TestInviteAcceptWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	h.Service.SetAcceptMethods(authpolicy.NewService(pool))
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

// TestInviteLookupOffersWhatAcceptAllows checks that the preview offers a
// password only where accepting with one is allowed, and a passkey only where
// the organization allows passkeys.
func TestInviteLookupOffersWhatAcceptAllows(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	h.Service.SetAcceptMethods(authpolicy.NewService(pool))
	for _, tc := range []struct {
		name              string
		password, passkey bool
	}{
		{"passwords on", true, false},
		{"passwords off", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			organization := dbtest.Organization(t)
			if _, err := pool.Exec(ctx, `INSERT INTO organization.auth_policy (organization_id, password_enabled, passkey_enabled) VALUES ($1, $2, $3)`,
				organization, tc.password, tc.passkey); err != nil {
				t.Fatalf("policy: %v", err)
			}
			_, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test"}, audit.Actor{})
			if err != nil {
				t.Fatalf("invite: %v", err)
			}
			preview, err := h.Service.Lookup(ctx, token)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if preview.Methods.Password != tc.password || preview.Methods.Passkey != tc.passkey {
				t.Errorf("lookup offers %+v, want password %v and passkey %v", preview.Methods, tc.password, tc.passkey)
			}
			_, err = h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{})
			if accepted := err == nil; accepted != preview.Methods.Password {
				t.Errorf("accept with a password: %v, but lookup offered a password: %v", err, preview.Methods.Password)
			}
		})
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
		t.Fatalf("my invitations %v, want the other organisation's %s", ids, inv.ID)
	}
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/"+inv.ID.String()+"/accept", nil); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2 AND role_id = $3`, a.ID, other, role); n != 1 {
		t.Error("accepting didn't give the invitation's role in its organisation")
	}
}

// inviteEvent is one audit event of an invitation: who acted, and its metadata.
type inviteEvent struct {
	Actor    *uuid.UUID
	Metadata map[string]any
}

// inviteEvents returns the action events recorded in organization for invitation id.
func inviteEvents(t *testing.T, organization, id uuid.UUID, action string) []inviteEvent {
	t.Helper()
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT actor_user_id, metadata FROM audit.events
		WHERE organization_id = $1 AND action = $2 AND resource_type = 'invite' AND resource_id = $3
	`, organization, action, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []inviteEvent
	for rows.Next() {
		var e inviteEvent
		var raw []byte
		if err := rows.Scan(&e.Actor, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &e.Metadata); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantInviteEvent checks that one action event was recorded for invitation id,
// by actor and naming email, and returns its metadata.
func wantInviteEvent(t *testing.T, organization, id uuid.UUID, action string, actor uuid.UUID, email string) map[string]any {
	t.Helper()
	got := inviteEvents(t, organization, id, action)
	if len(got) != 1 || got[0].Actor == nil || *got[0].Actor != actor || got[0].Metadata["email"] != email {
		t.Errorf("%s events of %s: %+v; want one by %s naming %s", action, id, got, actor, email)
		return map[string]any{}
	}
	return got[0].Metadata
}

// TestInvitationsAreAudited checks that creating, resending, revoking,
// accepting (with a password, a passkey, the emailed link while signed in, or
// from the inbox) and declining an invitation are each recorded with the
// change, by the administrator or the invitee, and never with the token.
func TestInvitationsAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	byAdmin := audit.Actor{UserID: &admin.ID, Type: "user"}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.MountAuthed)
	var tokens []string
	invite := func(email string, roleID *uuid.UUID) (*Invite, string) {
		t.Helper()
		inv, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: email, RoleID: roleID}, byAdmin)
		if err != nil {
			t.Fatalf("invite %s: %v", email, err)
		}
		tokens = append(tokens, token)
		return inv, token
	}

	email := dbtest.Unique("invitee") + "@example.test"
	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/invites", map[string]any{"email": email})
	var created struct {
		Invite Invite `json:"invite"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	id := created.Invite.ID
	wantInviteEvent(t, organization, id, "invite.created", admin.ID, email)
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/invites/"+id.String()+"/resend", nil); rec.Code != http.StatusOK {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body.String())
	}
	wantInviteEvent(t, organization, id, "invite.resent", admin.ID, email)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/invites/"+id.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	wantInviteEvent(t, organization, id, "invite.revoked", admin.ID, email)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/invites/"+id.String(), nil); rec.Code != http.StatusNotFound || len(inviteEvents(t, organization, id, "invite.revoked")) != 1 {
		t.Errorf("revoke twice: %d; want 404 and nothing more recorded", rec.Code)
	}

	role := dbtest.Role(t, organization)
	email = dbtest.Unique("invitee") + "@example.test"
	inv, token := invite(email, &role)
	res, err := h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{Type: "system", IP: "203.0.113.7"})
	if err != nil {
		t.Fatalf("accept with a password: %v", err)
	}
	if meta := wantInviteEvent(t, organization, inv.ID, "invite.accepted", res.UserID, email); meta["method"] != "password" || meta["role_id"] != role.String() {
		t.Errorf("accepted with a password: %v; want the method and the role", meta)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events
		WHERE resource_id = $1 AND action = 'invite.accepted' AND actor_type = 'user' AND host(ip) = '203.0.113.7'
	`, inv.ID); n != 1 {
		t.Error("the acceptance isn't recorded as the invitee's, from the request's address")
	}

	email = dbtest.Unique("invitee") + "@example.test"
	inv, _ = invite(email, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var newUser uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO account.users (organization_id, email) VALUES ($1, $2) RETURNING id`, organization, email).Scan(&newUser); err != nil {
		t.Fatal(err)
	}
	if err := h.Service.AcceptForNewAccountTx(ctx, tx, inv.ID, organization, newUser, email, "203.0.113.8", "test-agent"); err != nil {
		t.Fatalf("accept with a passkey: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if meta := wantInviteEvent(t, organization, inv.ID, "invite.accepted", newUser, email); meta["method"] != "passkey" {
		t.Errorf("accepted with a passkey: %v", meta)
	}

	home := dbtest.Organization(t)
	member := dbtest.User(t, home, home)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	asMember := dbtest.Serve(dbtest.Principal(member.ID, home), h.MountAuthed)
	byLink, linkToken := invite(member.Email, &role)
	byInbox, _ := invite(member.Email, &role)
	declined, _ := invite(member.Email, &role)
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/accept", map[string]string{"token": linkToken}); rec.Code != http.StatusOK {
		t.Fatalf("accept by link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/"+byInbox.ID.String()+"/accept", nil); rec.Code != http.StatusOK {
		t.Fatalf("accept from the inbox: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/"+declined.ID.String()+"/decline", nil); rec.Code != http.StatusOK {
		t.Fatalf("decline: %d %s", rec.Code, rec.Body.String())
	}
	for _, accepted := range []uuid.UUID{byLink.ID, byInbox.ID} {
		if meta := wantInviteEvent(t, organization, accepted, "invite.accepted", member.ID, member.Email); meta["method"] != "existing_account" {
			t.Errorf("accepted as a signed-in account: %v", meta)
		}
	}
	wantInviteEvent(t, organization, declined.ID, "invite.declined", member.ID, member.Email)

	for _, token := range tokens {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND strpos(metadata::text, $2) > 0`, organization, token); n != 0 {
			t.Errorf("an invitation's token is in %d audit events", n)
		}
	}
}

// TestInviteCreatesNoAccountOnAnotherOrganizationsDomain checks that an
// invitation to an address on a domain another organization has verified
// can't be accepted with a new account, by password or passkey, since the
// inviter also holds the link.
func TestInviteCreatesNoAccountOnAnotherOrganizationsDomain(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	organization := dbtest.Organization(t)
	claimed := dbtest.Unique("invitee") + "@" + dbtest.Domain(t, dbtest.Organization(t))
	_, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: claimed}, audit.Actor{})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{}); !errors.Is(err, errs.ErrUserDomainManaged) {
		t.Errorf("accept with a password: %v, want %v", err, errs.ErrUserDomainManaged)
	}
	if _, _, _, err := h.Service.InvitationForNewAccount(ctx, token); !errors.Is(err, errs.ErrUserDomainManaged) {
		t.Errorf("start accepting with a passkey: %v, want %v", err, errs.ErrUserDomainManaged)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, claimed); n != 0 {
		t.Errorf("the account was created")
	}
}

// TestInvitationsMatchAddressesAndNeedARoleForOutsiders checks that an
// invitation typed in another case reaches the account's inbox and is
// accepted, and that one with no role, to someone at home elsewhere, is
// refused rather than joining them to nothing.
func TestInvitationsMatchAddressesAndNeedARoleForOutsiders(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	byAdmin := audit.Actor{UserID: &admin.ID, Type: "user"}
	member := dbtest.UserAt(t, dbtest.Unique("bob")+"@example.test", home, home)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: strings.ToUpper(member.Email)}, byAdmin); !errors.Is(err, errs.ErrInviteRoleRequired) {
		t.Errorf("invite someone at home elsewhere with no role: %v, want %v", err, errs.ErrInviteRoleRequired)
	}
	role := dbtest.Role(t, organization)
	inv, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: "  " + strings.ToUpper(member.Email), RoleID: &role}, byAdmin)
	if err != nil {
		t.Fatalf("invite with a role: %v", err)
	}
	if inv.Email != strings.ToLower(member.Email) {
		t.Errorf("stored address %q, want it lower-case", inv.Email)
	}
	asMember := dbtest.Serve(dbtest.Principal(member.ID, home), h.MountAuthed)
	if rec := dbtest.Do(t, asMember, http.MethodGet, "/me/invites", nil); !strings.Contains(rec.Body.String(), inv.ID.String()) {
		t.Errorf("inbox: %d %s; want the invitation", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asMember, http.MethodPost, "/me/invites/"+inv.ID.String()+"/accept", nil); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, member.ID, organization); n != 1 {
		t.Errorf("%d roles in the organisation after accepting, want 1", n)
	}
}

// TestInvitationFromSomeoneNoLongerEntitledIsRefused checks that every way of
// accepting an invitation refuses it once whoever sent it may no longer give
// its role (demoted, suspended, removed from the organization or deleted),
// that removing or deleting them withdraws the invitations they sent, and
// that an invitation from someone still entitled is accepted.
func TestInvitationFromSomeoneNoLongerEntitledIsRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	svc := h.Service
	users := user.NewRepository(pool)
	organization := dbtest.Organization(t)
	invited := dbtest.Role(t, organization, "audit.read")
	inviterRole := dbtest.Role(t, organization, "member.invite", "audit.read")
	lesser := dbtest.Role(t, organization, "member.invite")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	inTx := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := f(tx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	changes := map[string]func(inviter uuid.UUID){
		"still entitled": func(uuid.UUID) {},
		"demoted": func(inviter uuid.UUID) {
			exec(`DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, inviter, organization)
			dbtest.Assign(t, inviter, organization, lesser)
		},
		"suspended": func(inviter uuid.UUID) { exec(`UPDATE account.users SET status = 'suspended' WHERE id = $1`, inviter) },
		"removed from the organisation": func(inviter uuid.UUID) {
			inTx(func(tx pgx.Tx) error {
				if _, err := users.RemoveFromOrganizationTx(ctx, tx, inviter, organization); err != nil {
					return err
				}
				return users.OffboardTx(ctx, tx, organization, inviter, audit.Actor{})
			})
		},
		"deleted": func(inviter uuid.UUID) {
			inTx(func(tx pgx.Tx) error {
				if _, err := users.SoftDeleteByTx(ctx, tx, inviter, nil); err != nil {
					return err
				}
				return users.OffboardTx(ctx, tx, organization, inviter, audit.Actor{})
			})
		},
	}
	// Each way of accepting, for the invitation inv sent to email with token.
	accepts := map[string]func(inv *Invite, token, email string) error{
		"a new account's password": func(_ *Invite, token, _ string) error {
			_, err := svc.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{})
			return err
		},
		"a new account's passkey": func(inv *Invite, token, _ string) error {
			if _, _, _, err := svc.InvitationForNewAccount(ctx, token); err != nil {
				return err
			}
			return svc.CheckInvitationSender(ctx, inv.ID)
		},
		"an existing account's link": func(_ *Invite, token, email string) error {
			a := dbtest.UserAt(t, email, dbtest.Organization(t))
			_, err := svc.AcceptAuthenticated(ctx, a.ID, token, audit.Actor{})
			return err
		},
		"an existing account's inbox": func(inv *Invite, _, email string) error {
			a := dbtest.UserAt(t, email, dbtest.Organization(t))
			exec(`UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID)
			_, err := svc.AcceptAuthenticatedByID(ctx, a.ID, inv.ID, audit.Actor{})
			return err
		},
	}
	for change, apply := range changes {
		for way, accept := range accepts {
			inviter := dbtest.User(t, organization)
			dbtest.Assign(t, inviter.ID, organization, inviterRole)
			email := dbtest.Unique("invitee") + "@example.test"
			inv, token, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Email: email, RoleID: &invited}, audit.Actor{UserID: &inviter.ID, Type: "user"})
			if err != nil {
				t.Fatalf("invite: %v", err)
			}
			apply(inviter.ID)
			err = accept(inv, token, email)
			if change == "still entitled" {
				if err != nil {
					t.Errorf("%s accepts an invitation from someone %s: %v", way, change, err)
				}
				continue
			}
			if !errors.Is(err, errs.ErrInviteInvalid) {
				t.Errorf("%s accepts an invitation from someone %s: %v, want %v", way, change, err, errs.ErrInviteInvalid)
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles ur JOIN account.users u ON u.id = ur.user_id
				WHERE ur.organization_id = $1 AND ur.role_id = $2 AND u.email = $3`, organization, invited, email); n != 0 {
				t.Errorf("%s, from someone %s: the invited role was given", way, change)
			}
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.invites i JOIN account.users u ON u.id = i.invited_by
		WHERE i.organization_id = $1 AND i.status = 'pending' AND (u.deleted_at IS NOT NULL OR NOT EXISTS (
			SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id = $1))`, organization); n != 0 {
		t.Errorf("%d invitations from people removed or deleted are still pending, want them withdrawn", n)
	}
}

// TestInvitationListTakesTheOrganizationFromTheCaller checks that the list of
// invitations answers only for the caller's own organization, even without the
// router's organization guard in front: another organization's in the path is
// refused, not read.
func TestInvitationListTakesTheOrganizationFromTheCaller(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, mine, mine)
	theirEmail := dbtest.Unique("invitee") + "@example.test"
	if _, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: theirs, Email: theirEmail}, audit.Actor{}); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), dbtest.Principal(admin.ID, mine))))
		})
	})
	h.MountAuthed(r)
	rec := dbtest.Do(t, r, http.MethodGet, "/tenants/"+theirs.String()+"/invites", nil)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), theirEmail) {
		t.Errorf("list another organisation's invitations: %d %.120s, want 403", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, r, http.MethodGet, "/tenants/"+mine.String()+"/invites", nil); rec.Code != http.StatusOK {
		t.Errorf("list the caller's own: %d %s", rec.Code, rec.Body.String())
	}
}
