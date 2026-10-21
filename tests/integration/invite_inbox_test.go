//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestInvitationInboxNeedsAVerifiedAddress pins the in-app invitations inbox to
// a proven address. An account holding an invited address it never verified
// (anyone can sign up with any address) must not see, accept or decline that
// invitation; once the address is verified, it can.
func TestInvitationInboxNeedsAVerifiedAddress(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := invite.NewService(testPool, &mailbox{}, 0, "http://console.test")

	tenantID := createTenant(t, ctx, uniqueSlug("inbox"))
	var roleID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'admin', FALSE) RETURNING id`,
		tenantID).Scan(&roleID); err != nil {
		t.Fatalf("create role: %v", err)
	}
	email := uniqueSlug("newhire") + "@corp.example"
	inv, _, err := svc.Create(ctx, invite.CreateInput{TenantID: tenantID, Email: email, RoleID: &roleID}, nil)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	// Someone signs up with the invited address before its owner does.
	var squatter uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, email).Scan(&squatter); err != nil {
		t.Fatalf("create account: %v", err)
	}
	status := func(t *testing.T) string {
		t.Helper()
		var s string
		if err := testPool.QueryRow(ctx, `SELECT status FROM tenant.invites WHERE id = $1`, inv.ID).Scan(&s); err != nil {
			t.Fatalf("read invite: %v", err)
		}
		return s
	}
	member := func(t *testing.T) bool {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, squatter, tenantID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n > 0
	}

	t.Run("an unverified address doesn't see the invitation", func(t *testing.T) {
		if _, err := svc.ListForUser(ctx, squatter); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
			t.Fatalf("err = %v, want %v", err, errs.ErrInviteEmailNotVerified)
		}
	})

	t.Run("an unverified address can't accept the invitation", func(t *testing.T) {
		if _, err := svc.AcceptAuthenticatedByID(ctx, squatter, inv.ID); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
			t.Fatalf("err = %v, want %v", err, errs.ErrInviteEmailNotVerified)
		}
		if member(t) || status(t) != "pending" {
			t.Fatalf("after a refused accept: member %v, invite %s", member(t), status(t))
		}
	})

	t.Run("an unverified address can't decline the invitation", func(t *testing.T) {
		if err := svc.DeclineForUser(ctx, squatter, inv.ID); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
			t.Fatalf("err = %v, want %v", err, errs.ErrInviteEmailNotVerified)
		}
		if status(t) != "pending" {
			t.Fatalf("invite = %s, want pending", status(t))
		}
	})

	t.Run("once the address is verified the invitation can be seen and accepted", func(t *testing.T) {
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET email_verified_at = $2 WHERE id = $1`, squatter, time.Now()); err != nil {
			t.Fatalf("verify: %v", err)
		}
		items, err := svc.ListForUser(ctx, squatter)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(items) != 1 || items[0].ID != inv.ID {
			t.Fatalf("inbox = %v, want the one invitation", items)
		}
		if _, err := svc.AcceptAuthenticatedByID(ctx, squatter, inv.ID); err != nil {
			t.Fatalf("accept: %v", err)
		}
		if !member(t) {
			t.Fatal("accepting did not add the membership")
		}
	})
}
