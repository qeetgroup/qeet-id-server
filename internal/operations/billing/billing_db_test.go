//go:build integration

package billing

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
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

// subscribe puts the organization on plan, as a completed checkout does.
func subscribe(t *testing.T, svc *Service, organization uuid.UUID, plan, currency string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := svc.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := svc.ChangePlan(ctx, tx, organization, plan, currency); err != nil {
		t.Fatalf("subscribe to %s: %v", plan, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// switchPlan runs SwitchPlan as the system.
func switchPlan(t *testing.T, svc *Service, organization uuid.UUID, plan, currency string) error {
	t.Helper()
	_, err := svc.SwitchPlan(dbtest.Context(t), organization, plan, currency, audit.Actor{Type: "system"})
	return err
}

// lapse ends the organization's paid period an hour ago, as if a month had passed
// with no renewal.
func lapse(t *testing.T, organization uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		UPDATE organization.subscriptions
		SET current_period_start = NOW() - interval '1 month 1 hour', current_period_end = NOW() - interval '1 hour'
		WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
}

// TestPlanLapsesAtPeriodEnd checks that a paid subscription keeps its plan
// past its period only for the payment grace, while its renewal is billed and
// paid, even if the renewal job never runs, and that one marked to cancel
// stops at its period end.
func TestPlanLapsesAtPeriodEnd(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	organization := dbtest.Organization(t)
	subscribe(t, svc, organization, "pro", "USD")
	sub, err := svc.GetSubscription(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	if !sub.Grants(time.Now()) {
		t.Fatalf("a new subscription grants nothing: %+v", sub)
	}
	lapse(t, organization)
	if sub, err = svc.GetSubscription(ctx, organization); err != nil {
		t.Fatal(err)
	}
	if !sub.Grants(time.Now()) {
		t.Errorf("a subscription just past its period, its renewal not yet billed, grants nothing")
	}
	if sub.Grants(time.Now().Add(DefaultPaymentGrace)) {
		t.Errorf("a subscription past its period and the payment grace still grants %s", sub.PlanCode)
	}
	cancelSubscription(t, svc, organization)
	if sub, err = svc.GetSubscription(ctx, organization); err != nil {
		t.Fatal(err)
	}
	if sub.Grants(time.Now()) {
		t.Errorf("a subscription marked to cancel still grants %s past its period", sub.PlanCode)
	}
}

// cancelSubscription marks the organization's subscription to end with its period.
func cancelSubscription(t *testing.T, svc *Service, organization uuid.UUID) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := svc.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := svc.Cancel(ctx, tx, organization); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// planOf returns the organization's subscribed plan code, or "" with none.
func planOf(t *testing.T, svc *Service, organization uuid.UUID) string {
	t.Helper()
	sub, err := svc.GetSubscription(dbtest.Context(t), organization)
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
		lapsed        bool   // from's paid period has ended
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
		{name: "refuses a cheaper plan once the paid period ended", from: "pro", fromCur: "USD", lapsed: true, to: "starter", toCur: "USD"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			organization := dbtest.Organization(t)
			switch {
			case c.trial:
				if _, err := svc.StartTrial(dbtest.Context(t), organization, c.from, c.fromCur); err != nil {
					t.Fatalf("start trial: %v", err)
				}
			case c.from != "":
				subscribe(t, svc, organization, c.from, c.fromCur)
			}
			if c.lapsed {
				lapse(t, organization)
			}
			invoices := dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1`, organization)
			before, err := svc.GetSubscription(dbtest.Context(t), organization)
			if err != nil {
				t.Fatal(err)
			}

			err = switchPlan(t, svc, organization, c.to, c.toCur)
			if c.wantSwitched {
				if err != nil {
					t.Fatalf("switch %q to %s: %v", c.from, c.to, err)
				}
				after, err := svc.GetSubscription(dbtest.Context(t), organization)
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
					if n := dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1`, organization); n != invoices {
						t.Errorf("switch within the paid period issued %d invoices", n-invoices)
					}
				}
				return
			}
			if !errors.Is(err, errs.ErrBillingCheckoutRequired) {
				t.Fatalf("switch %q to %s: %v, want %v", c.from, c.to, err, errs.ErrBillingCheckoutRequired)
			}
			if got := planOf(t, svc, organization); got != c.from {
				t.Errorf("plan after refusal = %q, want %q", got, c.from)
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1`, organization); n != invoices {
				t.Errorf("refusal issued %d invoices", n-invoices)
			}
		})
	}
}

func TestSwitchPlanUnderInvoiceOnlyBilling(t *testing.T) {
	svc := newTestService(t)
	svc.SetAllowUnpaidActivation(true)
	organization := dbtest.Organization(t)
	subscribe(t, svc, organization, "starter", "USD")

	// No card provider charges USD, so invoice-only billing activates the plan.
	if err := switchPlan(t, svc, organization, "pro", "USD"); err != nil {
		t.Fatalf("switch to pro: %v", err)
	}
	if got := planOf(t, svc, organization); got != "pro" {
		t.Fatalf("plan = %q, want pro", got)
	}

	// Once a card provider charges USD, a dearer plan goes through checkout.
	svc.SetPayments(NewPayments("", "", "", "", "").WithSandbox("http://localhost:8080", "test-webhook-secret"))
	if err := switchPlan(t, svc, organization, "enterprise", "USD"); !errors.Is(err, errs.ErrBillingCheckoutRequired) {
		t.Fatalf("switch to enterprise with a provider: %v, want %v", err, errs.ErrBillingCheckoutRequired)
	}
	if got := planOf(t, svc, organization); got != "pro" {
		t.Errorf("plan = %q, want pro", got)
	}
}

func TestPutSubscriptionAnswersCheckoutRequired(t *testing.T) {
	svc := newTestService(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	subscribe(t, svc, organization, "pro", "USD")
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	path := "/organizations/" + organization.String() + "/billing/subscription"

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
	if got := planOf(t, svc, organization); got != "starter" {
		t.Errorf("plan = %q, want starter", got)
	}
}

// gstIndia charges 18% GST as a seller in Karnataka.
var gstIndia = TaxConfig{Enabled: true, SellerCountry: "IN", SellerState: "Karnataka", GSTRateBps: 1800}

// withSandbox gives svc the sandbox card provider, which serves every checkout.
func withSandbox(svc *Service) {
	svc.SetPayments(NewPayments("", "", "", "", "").WithSandbox("http://localhost:8080", "test-webhook-secret"))
}

// sandboxCharge returns the checkout reference and the amount the sandbox
// provider was asked to charge, read from its hosted-checkout URL.
func sandboxCharge(t *testing.T, res *CheckoutResult) (string, int64) {
	t.Helper()
	if res == nil || res.Status != "checkout" {
		t.Fatalf("checkout result = %+v, want a hosted checkout", res)
	}
	u, err := url.Parse(res.CheckoutURL)
	if err != nil {
		t.Fatal(err)
	}
	amount, err := strconv.ParseInt(u.Query().Get("amount"), 10, 64)
	if err != nil {
		t.Fatalf("checkout URL %q has no amount", res.CheckoutURL)
	}
	return u.Query().Get("ref"), amount
}

// latestInvoice returns the organization's newest invoice.
func latestInvoice(t *testing.T, svc *Service, organization uuid.UUID) Invoice {
	t.Helper()
	invoices, err := svc.ListInvoices(dbtest.Context(t), organization)
	if err != nil {
		t.Fatal(err)
	}
	if len(invoices) == 0 {
		t.Fatalf("organization %s has no invoice", organization)
	}
	return invoices[0]
}

// serial is the series number at the end of an invoice number.
func serial(t *testing.T, inv Invoice) int {
	t.Helper()
	fy := financialYear(time.Now())
	if inv.Number == nil || !strings.HasPrefix(*inv.Number, fy+"/") {
		t.Fatalf("invoice number = %v, want one in the %s series", inv.Number, fy)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(*inv.Number, fy+"/"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCheckoutChargesTheInvoiceTotal checks that the provider is asked for the
// total tax included, and that the paid invoice shows that charge even when the
// billing profile changes before the payment completes.
func TestCheckoutChargesTheInvoiceTotal(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	svc.SetTaxConfig(gstIndia)
	withSandbox(svc)
	organization := dbtest.Organization(t)
	if err := svc.UpsertBillingProfile(ctx, organization, BillingProfile{Country: "IN", State: "Maharashtra"}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Checkout(ctx, organization, "starter", "INR", "IN", "https://app.example/ok", "https://app.example/cancel")
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	ref, charged := sandboxCharge(t, res)
	if charged != 283200 {
		t.Fatalf("provider asked to charge %d, want 283200 (2400.00 plus 18%% GST)", charged)
	}
	if err := svc.UpsertBillingProfile(ctx, organization, BillingProfile{Country: "US"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteCheckout(ctx, ref, nil); err != nil {
		t.Fatalf("complete checkout: %v", err)
	}

	inv := latestInvoice(t, svc, organization)
	if inv.AmountMinor != 283200 || inv.TaxableMinor != 240000 || inv.TaxMinor != 43200 || inv.TaxType != TaxTypeGSTInter {
		t.Errorf("invoice charges %d = %d + %d (%s), want 283200 = 240000 + 43200 (%s)",
			inv.AmountMinor, inv.TaxableMinor, inv.TaxMinor, inv.TaxType, TaxTypeGSTInter)
	}
	if inv.Status != "paid" {
		t.Errorf("invoice status = %q, want paid", inv.Status)
	}
	serial(t, inv)
}

// TestInvoiceStatusFollowsPayment checks that a plan granted without payment
// leaves its invoice open, that a free plan's is paid, and that charged
// invoices are numbered one after another.
func TestInvoiceStatusFollowsPayment(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	svc.SetTaxConfig(gstIndia)
	svc.SetAllowUnpaidActivation(true)

	first, second := dbtest.Organization(t), dbtest.Organization(t)
	for _, organization := range []uuid.UUID{first, second} {
		res, err := svc.Checkout(ctx, organization, "starter", "INR", "IN", "https://app.example/ok", "https://app.example/cancel")
		if err != nil || res.Status != "active" {
			t.Fatalf("invoice-only checkout: %+v, %v", res, err)
		}
	}
	inv := latestInvoice(t, svc, first)
	if inv.Status != "open" || inv.AmountMinor != 283200 {
		t.Errorf("invoice-only invoice: status %q, amount %d; want open, 283200", inv.Status, inv.AmountMinor)
	}
	if a, b := serial(t, inv), serial(t, latestInvoice(t, svc, second)); b != a+1 {
		t.Errorf("invoice numbers %d then %d, want consecutive", a, b)
	}

	free := dbtest.Organization(t)
	if _, err := svc.Checkout(ctx, free, "free", "INR", "IN", "https://app.example/ok", "https://app.example/cancel"); err != nil {
		t.Fatalf("free checkout: %v", err)
	}
	inv = latestInvoice(t, svc, free)
	if inv.Status != "paid" || inv.AmountMinor != 0 || inv.Number != nil {
		t.Errorf("free invoice: status %q, amount %d, number %v; want paid, 0, none", inv.Status, inv.AmountMinor, inv.Number)
	}
}

// TestSignupCheckoutChargesTheInvoiceTotal checks that a paid plan chosen at
// signup is charged tax included, taxed by the billing country given, and that
// the new organization's invoice shows that charge.
func TestSignupCheckoutChargesTheInvoiceTotal(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	svc.SetTaxConfig(gstIndia)
	withSandbox(svc)
	svc.SetOrgProvisioner(orgProvisioner{pool: dbtest.Pool(t)})

	res, err := svc.StartSignupCheckout(ctx, dbtest.User(t, uuid.Nil).ID, SignupCheckoutInput{
		OrgName: "Example", OrgSlug: dbtest.Unique("org"), PlanCode: "pro", Currency: "INR", Country: "IN",
		SuccessURL: "https://app.example/ok", CancelURL: "https://app.example/cancel",
	})
	if err != nil {
		t.Fatalf("signup checkout: %v", err)
	}
	ref, charged := sandboxCharge(t, res)
	if charged != 944000 {
		t.Fatalf("provider asked to charge %d, want 944000 (8000.00 plus 18%% GST)", charged)
	}
	if err := svc.CompleteCheckout(ctx, ref, nil); err != nil {
		t.Fatalf("complete checkout: %v", err)
	}
	var org uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT organization_id FROM organization.signup_checkouts WHERE id = $1`, ref).Scan(&org); err != nil {
		t.Fatal(err)
	}
	inv := latestInvoice(t, svc, org)
	if inv.AmountMinor != 944000 || inv.TaxMinor != 144000 || inv.Status != "paid" {
		t.Errorf("invoice: amount %d, tax %d, status %q; want 944000, 144000, paid", inv.AmountMinor, inv.TaxMinor, inv.Status)
	}
}

// orgProvisioner creates a signup checkout's organization as a bare row.
type orgProvisioner struct{ pool *pgxpool.Pool }

func (p orgProvisioner) ProvisionOrg(ctx context.Context, _ uuid.UUID, name, slug, _, _ string) (uuid.UUID, error) {
	var id uuid.UUID
	err := p.pool.QueryRow(ctx, `INSERT INTO organization.organizations (slug, name) VALUES ($1, $2) RETURNING id`, slug, name).Scan(&id)
	return id, err
}

// TestCompleteCheckoutUsesOneConnection checks that completing an organization
// checkout and a signup checkout each needs only one connection at a time,
// and that a repeated completion changes nothing.
func TestCompleteCheckoutUsesOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t)
	svc.SetOrgProvisioner(orgProvisioner{pool: pool})
	organization := dbtest.Organization(t)
	organizationCheckout, err := svc.q.InsertBillingCheckout(ctx, dbgen.InsertBillingCheckoutParams{
		OrganizationID: organization, Provider: "sandbox", PlanCode: "starter", Currency: "USD", AmountMinor: 2900, TaxType: TaxTypeNone,
	})
	if err != nil {
		t.Fatalf("stage organization checkout: %v", err)
	}
	var signupCheckout uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO organization.signup_checkouts (user_id, org_name, org_slug, plan_code, currency, provider, amount_minor)
		VALUES ($1, 'Example', $2, 'pro', 'USD', 'sandbox', 9900)
		RETURNING id
	`, dbtest.User(t, uuid.Nil).ID, dbtest.Unique("org")).Scan(&signupCheckout); err != nil {
		t.Fatalf("stage signup checkout: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	completeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, ref := range []uuid.UUID{organizationCheckout, signupCheckout, organizationCheckout, signupCheckout} {
		if err := svc.CompleteCheckout(completeCtx, ref.String(), nil); err != nil {
			t.Fatalf("complete checkout %s with one free connection: %v", ref, err)
		}
	}

	if got := planOf(t, svc, organization); got != "starter" {
		t.Errorf("organization checkout: plan = %q, want starter", got)
	}
	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT organization_id FROM organization.signup_checkouts WHERE id = $1 AND status = 'completed'`,
		signupCheckout).Scan(&org); err != nil {
		t.Fatalf("signup checkout not completed: %v", err)
	}
	if got := planOf(t, svc, org); got != "pro" {
		t.Errorf("signup checkout: plan = %q, want pro", got)
	}
	for _, id := range []uuid.UUID{organization, org} {
		if n := dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1`, id); n != 1 {
			t.Errorf("organization %s has %d invoices, want 1", id, n)
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
		INSERT INTO organization.signup_checkouts (user_id, org_name, org_slug, plan_code, currency, provider, amount_minor)
		VALUES ($1, $2, $3, 'no_such_plan', 'USD', 'sandbox', 9900)
		RETURNING id
	`, dbtest.User(t, uuid.Nil).ID, name, dbtest.Unique("org")).Scan(&checkout); err != nil {
		t.Fatalf("stage signup checkout: %v", err)
	}
	if err := svc.CompleteCheckout(ctx, checkout.String(), nil); err == nil {
		t.Fatal("completing a checkout for an unknown plan succeeded")
	}
	var status string
	var org *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT status, organization_id FROM organization.signup_checkouts WHERE id = $1`, checkout).Scan(&status, &org); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || org == nil {
		t.Fatalf("after the failure: status %q, organization %v; want pending with the organization recorded", status, org)
	}

	if _, err := pool.Exec(ctx, `UPDATE organization.signup_checkouts SET plan_code = 'pro' WHERE id = $1`, checkout); err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteCheckout(ctx, checkout.String(), nil); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.organizations WHERE name = $1`, name); n != 1 {
		t.Errorf("%d organizations for one checkout, want 1", n)
	}
	if got := planOf(t, svc, *org); got != "pro" {
		t.Errorf("plan after the retry = %q, want pro", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.signup_checkouts WHERE id = $1 AND status = 'completed' AND organization_id = $2`, checkout, *org); n != 1 {
		t.Error("the retried checkout is not completed with its organization")
	}
}

// refuseAudit makes the organization's audit writes of action fail until t
// ends, as an audit store that is down would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, name := dbtest.Owner(t), "refuse_"+strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := owner.Exec(dbtest.Context(t), `
		CREATE FUNCTION pg_temp.`+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store down'; END $$;
		CREATE TRIGGER `+name+` BEFORE INSERT ON audit.events FOR EACH ROW
		WHEN (NEW.organization_id = '`+organization.String()+`' AND NEW.action = '`+action+`') EXECUTE FUNCTION pg_temp.`+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP FUNCTION pg_temp.`+name+`() CASCADE`) })
}
