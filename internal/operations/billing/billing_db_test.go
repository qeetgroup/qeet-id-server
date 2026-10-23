//go:build integration

package billing

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newTestService returns a Service over the test database with the built-in
// plans seeded.
func newTestService(t *testing.T) *Service {
	t.Helper()
	svc := NewService(dbtest.Pool(t))
	if err := svc.SeedBuiltins(dbtest.Context(t)); err != nil {
		t.Fatalf("seed plans: %v", err)
	}
	return svc
}

// subscribe puts the tenant on plan, as a completed checkout does.
func subscribe(t *testing.T, svc *Service, tenant uuid.UUID, plan, currency string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := svc.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := svc.ChangePlan(ctx, tx, tenant, plan, currency); err != nil {
		t.Fatalf("subscribe to %s: %v", plan, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// switchPlan runs SwitchPlan in a transaction and commits it on success.
func switchPlan(t *testing.T, svc *Service, tenant uuid.UUID, plan, currency string) error {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := svc.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := svc.SwitchPlan(ctx, tx, tenant, plan, currency); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return nil
}

// planOf returns the tenant's subscribed plan code, or "" with none.
func planOf(t *testing.T, svc *Service, tenant uuid.UUID) string {
	t.Helper()
	sub, err := svc.GetSubscription(dbtest.Context(t), tenant)
	if err != nil {
		t.Fatalf("get subscription: %v", err)
	}
	return sub.PlanCode
}

func TestSwitchPlan(t *testing.T) {
	svc := newTestService(t)
	cases := []struct {
		name          string
		from, fromCur string // current plan; "" for no subscription
		trial         bool   // from is a trial rather than a paid plan
		to, toCur     string
		wantSwitched  bool
		keepsPeriod   bool // the paid period stays, with no new invoice
	}{
		{name: "refuses a plan that costs more", from: "starter", fromCur: "USD", to: "pro", toCur: "USD"},
		{name: "allows a plan that costs less", from: "pro", fromCur: "USD", to: "starter", toCur: "USD", wantSwitched: true, keepsPeriod: true},
		{name: "allows the free plan", from: "pro", fromCur: "USD", to: "free", toCur: "USD", wantSwitched: true},
		{name: "allows a plan at the same price", from: "pro", fromCur: "USD", to: "pro", toCur: "USD", wantSwitched: true, keepsPeriod: true},
		{name: "allows the free plan without a subscription", to: "free", toCur: "INR", wantSwitched: true},
		{name: "refuses a paid plan without a subscription", to: "starter", toCur: "USD"},
		{name: "refuses a paid plan during a trial", from: "pro", fromCur: "USD", trial: true, to: "starter", toCur: "USD"},
		{name: "refuses a paid plan in another currency", from: "pro", fromCur: "USD", to: "starter", toCur: "INR"},
		{name: "refuses a paid plan with another interval", from: "pro_year", fromCur: "USD", to: "starter", toCur: "USD"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tenant := dbtest.Tenant(t)
			switch {
			case c.trial:
				if _, err := svc.StartTrial(dbtest.Context(t), tenant, c.from, c.fromCur); err != nil {
					t.Fatalf("start trial: %v", err)
				}
			case c.from != "":
				subscribe(t, svc, tenant, c.from, c.fromCur)
			}
			invoices := dbtest.Count(t, `SELECT count(*) FROM tenant.invoices WHERE tenant_id = $1`, tenant)
			before, err := svc.GetSubscription(dbtest.Context(t), tenant)
			if err != nil {
				t.Fatal(err)
			}

			err = switchPlan(t, svc, tenant, c.to, c.toCur)
			if c.wantSwitched {
				if err != nil {
					t.Fatalf("switch %q to %s: %v", c.from, c.to, err)
				}
				after, err := svc.GetSubscription(dbtest.Context(t), tenant)
				if err != nil {
					t.Fatal(err)
				}
				if after.PlanCode != c.to {
					t.Errorf("plan after switch = %q, want %q", after.PlanCode, c.to)
				}
				if c.keepsPeriod {
					if !after.CurrentPeriodEnd.Equal(*before.CurrentPeriodEnd) {
						t.Errorf("period end moved from %v to %v", before.CurrentPeriodEnd, after.CurrentPeriodEnd)
					}
					if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invoices WHERE tenant_id = $1`, tenant); n != invoices {
						t.Errorf("switch within the paid period issued %d invoices", n-invoices)
					}
				}
				return
			}
			if !errors.Is(err, errs.ErrBillingCheckoutRequired) {
				t.Fatalf("switch %q to %s: %v, want %v", c.from, c.to, err, errs.ErrBillingCheckoutRequired)
			}
			if got := planOf(t, svc, tenant); got != c.from {
				t.Errorf("plan after refusal = %q, want %q", got, c.from)
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invoices WHERE tenant_id = $1`, tenant); n != invoices {
				t.Errorf("refusal issued %d invoices", n-invoices)
			}
		})
	}
}

func TestSwitchPlanUnderInvoiceOnlyBilling(t *testing.T) {
	svc := newTestService(t)
	svc.SetAllowUnpaidActivation(true)
	tenant := dbtest.Tenant(t)
	subscribe(t, svc, tenant, "starter", "USD")

	// No card provider charges USD, so invoice-only billing activates the plan.
	if err := switchPlan(t, svc, tenant, "pro", "USD"); err != nil {
		t.Fatalf("switch to pro: %v", err)
	}
	if got := planOf(t, svc, tenant); got != "pro" {
		t.Fatalf("plan = %q, want pro", got)
	}

	// Once a card provider charges USD, a dearer plan goes through checkout.
	svc.SetPayments(NewPayments("", "", "", "", "").WithSandbox("http://localhost:8080", "test-webhook-secret"))
	if err := switchPlan(t, svc, tenant, "enterprise", "USD"); !errors.Is(err, errs.ErrBillingCheckoutRequired) {
		t.Fatalf("switch to enterprise with a provider: %v, want %v", err, errs.ErrBillingCheckoutRequired)
	}
	if got := planOf(t, svc, tenant); got != "pro" {
		t.Errorf("plan = %q, want pro", got)
	}
}

func TestPutSubscriptionAnswersCheckoutRequired(t *testing.T) {
	svc := newTestService(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	subscribe(t, svc, tenant, "pro", "USD")
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	path := "/tenants/" + tenant.String() + "/billing/subscription"

	rec := dbtest.Do(t, h, http.MethodPut, path, map[string]string{"plan_code": "enterprise", "currency": "USD"})
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusPaymentRequired || body.Error.Code != errs.CodeBillingCheckoutRequired {
		t.Errorf("PUT enterprise: status %d, code %q; want %d, %q",
			rec.Code, body.Error.Code, http.StatusPaymentRequired, errs.CodeBillingCheckoutRequired)
	}

	if rec := dbtest.Do(t, h, http.MethodPut, path, map[string]string{"plan_code": "starter", "currency": "USD"}); rec.Code != http.StatusOK {
		t.Errorf("PUT starter: status %d, want 200; body %s", rec.Code, rec.Body)
	}
	if got := planOf(t, svc, tenant); got != "starter" {
		t.Errorf("plan = %q, want starter", got)
	}
}

// orgProvisioner creates a signup checkout's organization as a bare tenant.
type orgProvisioner struct{ pool *pgxpool.Pool }

func (p orgProvisioner) ProvisionOrg(ctx context.Context, _ uuid.UUID, name, slug, _, _ string) (uuid.UUID, error) {
	var id uuid.UUID
	err := p.pool.QueryRow(ctx, `INSERT INTO tenant.tenants (slug, name) VALUES ($1, $2) RETURNING id`, slug, name).Scan(&id)
	return id, err
}

// TestCompleteCheckoutUsesOneConnection checks that completing a tenant
// checkout and a signup checkout each needs only one connection at a time,
// and that a repeated completion changes nothing.
func TestCompleteCheckoutUsesOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t)
	svc.SetOrgProvisioner(orgProvisioner{pool: pool})
	tenant := dbtest.Tenant(t)
	tenantCheckout, err := svc.q.InsertBillingCheckout(ctx, dbgen.InsertBillingCheckoutParams{
		TenantID: tenant, Provider: "sandbox", PlanCode: "starter", Currency: "USD", AmountMinor: 2900,
	})
	if err != nil {
		t.Fatalf("stage tenant checkout: %v", err)
	}
	var signupCheckout uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.signup_checkouts (user_id, org_name, org_slug, plan_code, currency, provider, amount_minor)
		VALUES ($1, 'Example', $2, 'pro', 'USD', 'sandbox', 9900)
		RETURNING id
	`, dbtest.User(t, uuid.Nil).ID, dbtest.Unique("org")).Scan(&signupCheckout); err != nil {
		t.Fatalf("stage signup checkout: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	completeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, ref := range []uuid.UUID{tenantCheckout, signupCheckout, tenantCheckout, signupCheckout} {
		if err := svc.CompleteCheckout(completeCtx, ref.String()); err != nil {
			t.Fatalf("complete checkout %s with one free connection: %v", ref, err)
		}
	}

	if got := planOf(t, svc, tenant); got != "starter" {
		t.Errorf("tenant checkout: plan = %q, want starter", got)
	}
	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM tenant.signup_checkouts WHERE id = $1 AND status = 'completed'`,
		signupCheckout).Scan(&org); err != nil {
		t.Fatalf("signup checkout not completed: %v", err)
	}
	if got := planOf(t, svc, org); got != "pro" {
		t.Errorf("signup checkout: plan = %q, want pro", got)
	}
	for _, id := range []uuid.UUID{tenant, org} {
		if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invoices WHERE tenant_id = $1`, id); n != 1 {
			t.Errorf("tenant %s has %d invoices, want 1", id, n)
		}
	}
}

// TestSignupCheckoutResumesAfterAFailure checks that a signup checkout whose
// plan can't be activated returns to pending with its organization recorded,
// and that the retry activates the plan on that organization, creating no
// second one.
func TestSignupCheckoutResumesAfterAFailure(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t)
	svc.SetOrgProvisioner(orgProvisioner{pool: pool})
	name := dbtest.Unique("Resume")
	var checkout uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.signup_checkouts (user_id, org_name, org_slug, plan_code, currency, provider, amount_minor)
		VALUES ($1, $2, $3, 'no_such_plan', 'USD', 'sandbox', 9900)
		RETURNING id
	`, dbtest.User(t, uuid.Nil).ID, name, dbtest.Unique("org")).Scan(&checkout); err != nil {
		t.Fatalf("stage signup checkout: %v", err)
	}
	if err := svc.CompleteCheckout(ctx, checkout.String()); err == nil {
		t.Fatal("completing a checkout for an unknown plan succeeded")
	}
	var status string
	var org *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT status, tenant_id FROM tenant.signup_checkouts WHERE id = $1`, checkout).Scan(&status, &org); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || org == nil {
		t.Fatalf("after the failure: status %q, organization %v; want pending with the organization recorded", status, org)
	}

	if _, err := pool.Exec(ctx, `UPDATE tenant.signup_checkouts SET plan_code = 'pro' WHERE id = $1`, checkout); err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteCheckout(ctx, checkout.String()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.tenants WHERE name = $1`, name); n != 1 {
		t.Errorf("%d organizations for one checkout, want 1", n)
	}
	if got := planOf(t, svc, *org); got != "pro" {
		t.Errorf("plan after the retry = %q, want pro", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.signup_checkouts WHERE id = $1 AND status = 'completed' AND tenant_id = $2`, checkout, *org); n != 1 {
		t.Error("the retried checkout is not completed with its organization")
	}
}
