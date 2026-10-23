//go:build integration

package invite

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPassword = "Kx7mQ2vLp9Wz"

// newHandler wires the invitation handler as bootstrap does.
func newHandler(t *testing.T) (*Handler, *auth.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	svc := NewService(pool, &dbtest.Mailbox{}, 0, "https://console.example.test")
	svc.SetPasswordRules(authpolicy.NewService(pool))
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	h := &Handler{
		Service:     svc,
		AuthService: authSvc,
		Validate:    validator.New(validator.WithRequiredStructEnabled()),
		GrantCheck:  rbac.NewRepository(pool).CheckGrantRole,
	}
	return h, authSvc
}

// TestInvitesStayInTheirTenant checks that one tenant can neither list, resend
// nor revoke another tenant's invitation, and that only the invited address
// can accept it.
func TestInvitesStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)
	inviteA, tokenA, err := h.Service.Create(ctx, CreateInput{TenantID: tenantA, Email: dbtest.Unique("invitee") + "@example.test"}, nil)
	if err != nil {
		t.Fatalf("invite in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), h.MountAuthed)
	path := "/invites/" + inviteA.ID.String()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, path + "/resend", http.StatusNotFound},
		{http.MethodDelete, path, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/invites", http.StatusForbidden},
		{http.MethodPost, "/me/invites/" + inviteA.ID.String() + "/accept", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/invites", nil)); slices.Contains(ids, inviteA.ID) {
		t.Error("tenant B's invitation list includes tenant A's")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM tenant.invites WHERE id = $1 AND status = 'pending' AND token_hash = $2
	`, inviteA.ID, codes.Hash(tokenA)); n != 1 {
		t.Error("tenant B changed tenant A's invitation")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, adminB.ID, tenantA); n != 0 {
		t.Error("tenant B's admin joined tenant A")
	}
}

// TestInviteAccept checks that accepting an invitation creates the account in
// the inviting tenant with the invited role, signs it in there, and spends the
// invitation.
func TestInviteAccept(t *testing.T) {
	ctx := dbtest.Context(t)
	h, authSvc := newHandler(t)
	tenant := dbtest.Tenant(t)
	role := dbtest.Role(t, tenant)
	email := dbtest.Unique("invitee") + "@example.test"
	inv, token, err := h.Service.Create(ctx, CreateInput{TenantID: tenant, Email: email, RoleID: &role}, nil)
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
	if pair.AccessToken == "" || pair.TenantID == nil || *pair.TenantID != tenant {
		t.Fatalf("accept signed in to tenant %v, want %s", pair.TenantID, tenant)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM "user".users u JOIN rbac.user_roles ur ON ur.user_id = u.id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.email = $3 AND ur.tenant_id = $2 AND ur.role_id = $4
	`, pair.UserID, tenant, email, role); n != 1 {
		t.Error("the accepted account is not a member of the inviting tenant with the invited role")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invites WHERE id = $1 AND status = 'accepted'`, inv.ID); n != 1 {
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
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.MountAuthed)

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
// only one connection free, while the organisation's sign-in methods and
// password rules are read from the database.
func TestInviteAcceptWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	h.Service.SetAcceptMethods(authpolicy.NewService(pool))
	tenant := dbtest.Tenant(t)
	_, token, err := h.Service.Create(ctx, CreateInput{TenantID: tenant, Email: dbtest.Unique("invitee") + "@example.test"}, nil)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	if res, err := h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}); err != nil || res.TenantID != tenant {
		t.Fatalf("accept: %+v, %v; want an account in %s", res, err, tenant)
	}
}

// TestInviteLookupOffersWhatAcceptAllows checks that the preview offers a
// password only where accepting with one is allowed, and a passkey only where
// the organisation allows passkeys.
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
			tenant := dbtest.Tenant(t)
			if _, err := pool.Exec(ctx, `INSERT INTO tenant.auth_policy (tenant_id, password_enabled, passkey_enabled) VALUES ($1, $2, $3)`,
				tenant, tc.password, tc.passkey); err != nil {
				t.Fatalf("policy: %v", err)
			}
			_, token, err := h.Service.Create(ctx, CreateInput{TenantID: tenant, Email: dbtest.Unique("invitee") + "@example.test"}, nil)
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
			_, err = h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword})
			if accepted := err == nil; accepted != preview.Methods.Password {
				t.Errorf("accept with a password: %v, but lookup offered a password: %v", err, preview.Methods.Password)
			}
		})
	}
}
