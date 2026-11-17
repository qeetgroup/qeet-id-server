//go:build integration

package invite

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
	for name, role := range map[string]uuid.UUID{"another tenant's role": roleA, "a missing role": uuid.New()} {
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
	if answers["another tenant's role"] != answers["a missing role"] {
		t.Errorf("another tenant's role is answered %+v, a missing one %+v", answers["another tenant's role"], answers["a missing role"])
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
		t.Errorf("an invitation carrying another tenant's role was stored: %v, want a foreign key violation", err)
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
