//go:build integration

package invite

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
		{http.MethodGet, "/organizations/" + organizationA.String() + "/invites", http.StatusForbidden},
		{http.MethodPost, "/me/invites/" + inviteA.ID.String() + "/accept", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/invites", nil)); slices.Contains(ids, inviteA.ID) {
		t.Error("organization B's invitation list includes organization A's")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM organization.invites WHERE id = $1 AND status = 'pending' AND token_hash = $2
	`, inviteA.ID, codes.Hash(tokenA)); n != 1 {
		t.Error("organization B changed organization A's invitation")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, adminB.ID, organizationA); n != 0 {
		t.Error("organization B's admin joined organization A")
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
	if _, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: strings.ToUpper(member.Email)}, byAdmin); !errors.Is(err, ErrRoleRequired) {
		t.Errorf("invite someone at home elsewhere with no role: %v, want %v", err, ErrRoleRequired)
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
		t.Errorf("%d roles in the organization after accepting, want 1", n)
	}
}

// TestInviteRoleMustBelongToTheOrganization checks that an invitation can carry only
// a role of the inviting organization, answering another organization's role as a missing
// one, and that the database refuses to store one carrying another organization's.
func TestInviteRoleMustBelongToTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	roleA := dbtest.Role(t, organizationA, "users:write")
	adminB := dbtest.User(t, organizationB, organizationB)
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), h.MountAuthed)

	type answer struct {
		Status                int
		Code, Message, Detail string
	}
	answers := map[string]answer{}
	for name, role := range map[string]uuid.UUID{"another organization's role": roleA, "a missing role": uuid.New()} {
		email := dbtest.Unique("invitee") + "@example.test"
		rec := dbtest.Do(t, asB, http.MethodPost, "/invites", map[string]any{"email": email, "role_id": role})
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Detail  string `json:"detail"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &body)
		answers[name] = answer{rec.Code, body.Error.Code, body.Error.Message, body.Error.Detail}
		if rec.Code != http.StatusNotFound || body.Error.Code != errs.CodeNotFound {
			t.Errorf("invite with %s: %d %s, want 404 %s (%s)", name, rec.Code, body.Error.Code, errs.CodeNotFound, rec.Body.String())
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM organization.invites WHERE email = $1`, email); n != 0 {
			t.Errorf("invite with %s was stored", name)
		}
	}
	if answers["another organization's role"] != answers["a missing role"] {
		t.Errorf("another organization's role is answered %+v, a missing one %+v", answers["another organization's role"], answers["a missing role"])
	}

	// Below the service too: the database won't store such an invitation.
	_, hash, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = dbtest.Pool(t).Exec(ctx, `
		INSERT INTO organization.invites (organization_id, email, role_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 day')
	`, organizationB, dbtest.Unique("invitee")+"@example.test", roleA, hash)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("an invitation carrying another organization's role was stored: %v, want a foreign key violation", err)
	}
}

// TestResendingAnInvitationNeedsItsRole checks that resending, and so reviving,
// an invitation carrying a role is held to the grant check creating it is:
// someone who may invite but doesn't hold the role's permissions is refused
// and the invitation stays as it was; one without a role, or a caller holding
// them, resends.
func TestResendingAnInvitationNeedsItsRole(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	organization := dbtest.Organization(t)
	powerful := dbtest.Role(t, organization, "user.write", "member.invite")
	invite := func(role *uuid.UUID) uuid.UUID {
		t.Helper()
		iv, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test", RoleID: role}, audit.Actor{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.invites SET status = 'expired' WHERE id = $1`, iv.ID); err != nil {
			t.Fatal(err)
		}
		return iv.ID
	}
	asCaller := func(permissions ...string) http.Handler {
		caller := dbtest.User(t, organization)
		dbtest.Assign(t, caller.ID, organization, dbtest.Role(t, organization, permissions...))
		return dbtest.Serve(dbtest.Principal(caller.ID, organization), h.MountAuthed)
	}
	inviter := asCaller("member.invite")

	withRole := invite(&powerful)
	if rec := dbtest.Do(t, inviter, http.MethodPost, "/invites/"+withRole.String()+"/resend", nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) {
		t.Errorf("resend an invitation to a role above the caller's: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.invites WHERE id = $1 AND status = 'expired'`, withRole); n != 1 {
		t.Error("a refused resend revived the invitation")
	}
	if rec := dbtest.Do(t, inviter, http.MethodPost, "/invites/"+invite(nil).String()+"/resend", nil); rec.Code != http.StatusOK {
		t.Errorf("resend an invitation without a role: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asCaller("user.write", "member.invite"), http.MethodPost, "/invites/"+withRole.String()+"/resend", nil); rec.Code != http.StatusOK {
		t.Errorf("resend it as a caller holding the role's permissions: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, inviter, http.MethodPost, "/invites/"+uuid.NewString()+"/resend", nil); rec.Code != http.StatusNotFound {
		t.Errorf("resend an unknown invitation: %d, want 404", rec.Code)
	}
}
