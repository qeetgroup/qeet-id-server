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

// TestSwitchAppliesTheTargetsRules checks that a switch from one organisation,
// a request scoped to it by row-level security, still applies the target
// organisation's second-factor rule, and enters one without such a rule.
func TestSwitchAppliesTheTargetsRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetMFA(&poolFactors{pool: pool})
	a, home := member(t)
	strict, open := dbtest.Tenant(t), dbtest.Tenant(t)
	for _, tenant := range []uuid.UUID{strict, open} {
		dbtest.Assign(t, a.ID, tenant, dbtest.Role(t, tenant))
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 0, NOW())
	`, strict); err != nil {
		t.Fatalf("require a second factor: %v", err)
	}
	pair := signIn(t, svc, a)
	p := dbtest.Principal(a.ID, home)
	p.SessionID = &pair.SessionID
	h := dbtest.Serve(p, (&Handler{Service: svc, Validate: validator.New(validator.WithRequiredStructEnabled())}).MountAuthed)
	switchTo := func(tenant uuid.UUID) (int, string) {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodPost, "/auth/switch-tenant", map[string]string{"tenant_id": tenant.String()})
		var body struct {
			TenantID uuid.UUID `json:"tenant_id"`
			Error    struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &body)
		if rec.Code == http.StatusOK && body.TenantID != tenant {
			t.Errorf("switched into %s, want %s", body.TenantID, tenant)
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

// TestOwnOrganisationNeedsNoRole checks that an account signs in to its own
// organisation and switches back into it holding no role there, while a guest
// whose roles were removed, or a suspended account, can't switch in.
func TestOwnOrganisationNeedsNoRole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	home, guestOf := dbtest.Tenant(t), dbtest.Tenant(t)
	a := dbtest.User(t, home, guestOf)
	dbtest.SetPassword(t, a.ID, testPassword)
	switchTo := func(from *TokenPair, tenant uuid.UUID) (*TokenPair, error) {
		return svc.SwitchTenant(ctx, SwitchTenantInput{UserID: a.ID, FromSessionID: from.SessionID, TenantID: tenant})
	}

	signedIn := signIn(t, svc, a)
	if signedIn.TenantID == nil || *signedIn.TenantID != home {
		t.Fatalf("signed in to %v, want their own organisation %s", signedIn.TenantID, home)
	}
	there, err := switchTo(signedIn, guestOf)
	if err != nil {
		t.Fatalf("switch into the organisation they hold a role in: %v", err)
	}
	back, err := switchTo(there, home)
	if err != nil || back.TenantID == nil || *back.TenantID != home {
		t.Fatalf("switch back into their own organisation: %+v, %v", back, err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, a.ID, guestOf); err != nil {
		t.Fatal(err)
	}
	if next, err := switchTo(back, guestOf); !errors.Is(err, errs.ErrAuthNotTenantMember) || next != nil {
		t.Errorf("switch into an organisation whose roles were removed: %+v, %v; want %v", next, err, errs.ErrAuthNotTenantMember)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if next, err := switchTo(back, home); !errors.Is(err, errs.ErrAuthNotTenantMember) || next != nil {
		t.Errorf("a suspended account switching into its own organisation: %+v, %v; want %v", next, err, errs.ErrAuthNotTenantMember)
	}
}
