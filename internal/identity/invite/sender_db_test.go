//go:build integration

package invite

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

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
		"removed from the organization": func(inviter uuid.UUID) {
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
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s accepts an invitation from someone %s: %v, want %v", way, change, err, ErrInvalid)
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
