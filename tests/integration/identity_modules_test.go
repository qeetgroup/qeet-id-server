//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Organizations: create a tenant with an owner, then read it back three ways
// (by id, by slug, and via the owner's membership list).
func TestTenantRepository_CreateOwnerGetList(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := tenant.NewRepository(testPool)

	// An owner user must already exist somewhere.
	boot := createTenant(t, ctx, uniqueSlug("boot"))
	owner := createTenantUser(t, ctx, boot, uniqueSlug("owner")+"@example.com")

	slug := uniqueSlug("org")
	tn, err := repo.CreateWithOwner(ctx, tenant.CreateInput{Slug: slug, Name: "Acme", Plan: "free"}, owner)
	if err != nil {
		t.Fatalf("CreateWithOwner: %v", err)
	}
	if tn.Slug != slug {
		t.Fatalf("slug = %q, want %q", tn.Slug, slug)
	}

	got, err := repo.Get(ctx, tn.ID)
	if err != nil || got.ID != tn.ID {
		t.Fatalf("Get: %v (got %+v)", err, got)
	}
	bySlug, err := repo.GetBySlug(ctx, slug)
	if err != nil || bySlug.ID != tn.ID {
		t.Fatalf("GetBySlug: %v (got %+v)", err, bySlug)
	}

	list, _, err := repo.List(ctx, owner, 50, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, x := range list {
		if x.ID == tn.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("List(owner) should include the owned tenant %s", tn.ID)
	}
}

func containsGroup(list []group.Group, id uuid.UUID) bool {
	for _, g := range list {
		if g.ID == id {
			return true
		}
	}
	return false
}

// Groups: full lifecycle — create, list, add/remove a member, delete.
func TestGroupService_CRUDAndMembership(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("grp"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	g, err := svc.Create(ctx, group.CreateInput{TenantID: tid, Name: "engineering"}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if list, err := svc.List(ctx, tid); err != nil || !containsGroup(list, g.ID) {
		t.Fatalf("List should include the new group (err=%v)", err)
	}

	u := createTenantUser(t, ctx, tid, uniqueSlug("member")+"@example.com")
	if err := svc.AddMember(ctx, g.ID, u, tid, actor); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if members, err := svc.ListMembers(ctx, g.ID, tid); err != nil || len(members) != 1 {
		t.Fatalf("ListMembers = %d (err=%v), want 1", len(members), err)
	}

	if err := svc.RemoveMember(ctx, g.ID, u, tid, actor); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if members, _ := svc.ListMembers(ctx, g.ID, tid); len(members) != 0 {
		t.Fatalf("after remove, members = %d, want 0", len(members))
	}

	if err := svc.Delete(ctx, g.ID, tid, actor); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if list, _ := svc.List(ctx, tid); containsGroup(list, g.ID) {
		t.Fatal("a deleted group should not be listed")
	}
}

// Invitations: an accepted invite provisions a real user in the tenant, and a
// revoked invite can no longer be accepted.
func TestInviteService_AcceptProvisionsUser_RevokeBlocks(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("inv"))
	svc := invite.NewService(testPool, &captureSender{}, time.Hour, "http://app.test")
	svc.SetPasswordRules(authpolicy.NewService(testPool))

	email := uniqueSlug("invitee") + "@example.com"
	_, raw, err := svc.Create(ctx, invite.CreateInput{TenantID: tid, Email: email}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := svc.Accept(ctx, invite.AcceptInput{Token: raw, Password: "Kx7mQ2vLp9Wz", DisplayName: "Invited User"})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if res.TenantID != tid {
		t.Fatalf("accepted into tenant %s, want %s", res.TenantID, tid)
	}
	var n int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM "user".users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)`,
		tid, email).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 provisioned user for %s, got %d", email, n)
	}

	// A revoked invite must not be acceptable.
	inv2, raw2, err := svc.Create(ctx, invite.CreateInput{TenantID: tid, Email: uniqueSlug("invitee2") + "@example.com"}, nil)
	if err != nil {
		t.Fatalf("Create (2): %v", err)
	}
	if err := svc.Revoke(ctx, tid, inv2.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Accept(ctx, invite.AcceptInput{Token: raw2, Password: "Kx7mQ2vLp9Wz"}); err == nil {
		t.Fatal("accepting a revoked invite should fail")
	}
}

var sixDigitCode = regexp.MustCompile(`\b\d{6}\b`)

// Verification: the emailed 6-digit code confirms the address (a wrong code is
// rejected; the right one sets email_verified_at).
// A resend must retire the previous code. Confirm matched on (user_id,
// code_hash), so every code issued stayed usable until it expired and the
// superseded one still verified the account.
func TestVerificationService_ResendInvalidatesPreviousCode(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("ver"))
	email := uniqueSlug("resend") + "@example.com"
	u := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := verification.NewService(testPool, sender, time.Hour)

	codeOf := func(step string) string {
		t.Helper()
		if err := svc.StartEmail(ctx, u, email); err != nil {
			t.Fatalf("StartEmail (%s): %v", step, err)
		}
		msg, ok := sender.last()
		if !ok {
			t.Fatalf("no verification email captured (%s)", step)
		}
		code := sixDigitCode.FindString(msg.Body)
		if code == "" {
			t.Fatalf("no 6-digit code in body (%s): %q", step, msg.Body)
		}
		return code
	}

	first := codeOf("first")
	second := codeOf("resend")
	if first == second {
		t.Skip("the two issued codes collided; nothing to distinguish")
	}

	if err := svc.ConfirmEmail(ctx, u, first); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		t.Fatalf("superseded code: err = %v, want ErrVerifyCodeInvalid", err)
	}

	var verifiedAt *time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT email_verified_at FROM "user".users WHERE id = $1`, u).Scan(&verifiedAt); err != nil {
		t.Fatalf("read email_verified_at: %v", err)
	}
	if verifiedAt != nil {
		t.Fatal("a superseded code must not verify the account")
	}

	if err := svc.ConfirmEmail(ctx, u, second); err != nil {
		t.Fatalf("ConfirmEmail (latest code): %v", err)
	}
}

// A 6-digit code is a million combinations, so guesses against one code must be
// budgeted. Nothing capped them before: a caller could grind the code for its
// whole lifetime and end up with an email address verified that they never
// controlled.
func TestVerificationService_WrongCodeAttemptsAreCapped(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("ver"))
	email := uniqueSlug("bruteforce") + "@example.com"
	u := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := verification.NewService(testPool, sender, time.Hour)
	if err := svc.StartEmail(ctx, u, email); err != nil {
		t.Fatalf("StartEmail: %v", err)
	}
	msg, ok := sender.last()
	if !ok {
		t.Fatal("no verification email captured")
	}
	code := sixDigitCode.FindString(msg.Body)

	wrong := func(i int) string {
		c := fmt.Sprintf("%06d", i)
		if c == code {
			c = fmt.Sprintf("%06d", i+1)
		}
		return c
	}

	// Budget is five guesses. The first four are plain wrong answers...
	for i := 0; i < 4; i++ {
		if err := svc.ConfirmEmail(ctx, u, wrong(i)); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
			t.Fatalf("guess %d: err = %v, want ErrVerifyCodeInvalid", i+1, err)
		}
	}
	// ...and the fifth is the one that spends the budget, so it says so rather
	// than making the user discover it on a sixth try.
	if err := svc.ConfirmEmail(ctx, u, wrong(4)); !errors.Is(err, errs.ErrVerifyAttemptsExceeded) {
		t.Fatalf("guess 5: err = %v, want ErrVerifyAttemptsExceeded", err)
	}

	// Budget gone: further guesses are refused outright.
	if err := svc.ConfirmEmail(ctx, u, wrong(99)); !errors.Is(err, errs.ErrVerifyAttemptsExceeded) {
		t.Fatalf("after budget: err = %v, want ErrVerifyAttemptsExceeded", err)
	}

	// And the code is dead even if the attacker now lands on the right value.
	if err := svc.ConfirmEmail(ctx, u, code); !errors.Is(err, errs.ErrVerifyAttemptsExceeded) {
		t.Fatalf("correct code after budget: err = %v, want ErrVerifyAttemptsExceeded", err)
	}
	var verifiedAt *time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT email_verified_at FROM "user".users WHERE id = $1`, u).Scan(&verifiedAt); err != nil {
		t.Fatalf("read email_verified_at: %v", err)
	}
	if verifiedAt != nil {
		t.Fatal("a burned code must never verify the account")
	}

	// A fresh code restores a full budget, so a genuine user is not locked out.
	if err := svc.StartEmail(ctx, u, email); err != nil {
		t.Fatalf("StartEmail (new code): %v", err)
	}
	msg, _ = sender.last()
	if err := svc.ConfirmEmail(ctx, u, sixDigitCode.FindString(msg.Body)); err != nil {
		t.Fatalf("confirm with a fresh code: %v", err)
	}
}

func TestVerificationService_EmailConfirm(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("ver"))
	email := uniqueSlug("verify") + "@example.com"
	u := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := verification.NewService(testPool, sender, time.Hour)

	if err := svc.StartEmail(ctx, u, email); err != nil {
		t.Fatalf("StartEmail: %v", err)
	}
	msg, ok := sender.last()
	if !ok {
		t.Fatal("no verification email captured")
	}
	code := sixDigitCode.FindString(msg.Body)
	if code == "" {
		t.Fatalf("no 6-digit code in body: %q", msg.Body)
	}

	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	if err := svc.ConfirmEmail(ctx, u, wrong); err == nil {
		t.Fatal("a wrong verification code should be rejected")
	}
	if err := svc.ConfirmEmail(ctx, u, code); err != nil {
		t.Fatalf("ConfirmEmail (correct code): %v", err)
	}

	var verifiedAt *time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT email_verified_at FROM "user".users WHERE id = $1`, u).Scan(&verifiedAt); err != nil {
		t.Fatalf("read email_verified_at: %v", err)
	}
	if verifiedAt == nil {
		t.Fatal("email_verified_at should be set after a successful confirm")
	}
}
