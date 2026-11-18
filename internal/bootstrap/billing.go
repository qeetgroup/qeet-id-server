package bootstrap

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// NewBillingService returns the billing service cfg configures: card providers
// routed by billing country, invoice-only billing, tax and the payment grace.
// organizations creates a paid signup's organization.
func NewBillingService(cfg *config.Config, pool *pgxpool.Pool, organizations *organization.Repository) (*billing.Service, error) {
	payments := billing.NewPayments(
		cfg.StripeSecretKey, cfg.StripeWebhookSecret,
		cfg.RazorpayKeyID, cfg.RazorpayKeySecret, cfg.RazorpayWebhookSecret,
	).WithRouting(cfg.PaymentDefaultProvider, billing.ParseCountryRoutes(cfg.PaymentCountryRoutes)) // card payments (Stripe/Razorpay), routed by billing country; no-op until keys are configured
	if cfg.PaymentSandbox {
		payments = payments.WithSandbox(cfg.PaymentSandboxBaseURL, "sandbox-dev-secret") // dev-only fake provider; config.Validate refuses it outside dev
	}
	svc, err := billing.NewService(pool, billing.Config{
		Payments:              payments,
		AllowUnpaidActivation: cfg.BillingAllowUnpaidActivation,                    // else a paid plan with no provider is refused, not granted free
		OrgProvisioner:        billingOrgProvisioner{organizations: organizations}, // creates the org when a signup checkout is paid
		PaymentGrace:          cfg.BillingPaymentGrace,                             // how long a renewal may go unpaid
		Tax: billing.TaxConfig{ // invoice GST/VAT (off unless configured)
			Enabled:       cfg.BillingTaxEnabled,
			SellerCountry: cfg.BillingSellerCountry,
			SellerState:   cfg.BillingSellerState,
			GSTRateBps:    cfg.BillingGSTRateBps,
			SupplierGSTIN: cfg.BillingSupplierGSTIN,
			SAC:           cfg.BillingSAC,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("billing service: %w", err)
	}
	return svc, nil
}

// Scheduler is what the standalone scheduler's billing and plan jobs run with,
// built as the API builds them: billing, the plans it resolves, and invoice
// emails through its own outbound mail chain.
type Scheduler struct {
	Billing  *billing.Service
	Plans    *entitlements.Service
	Invoices *billing.InvoiceEmails
}

// NewScheduler builds the standalone scheduler's billing, plans and invoice
// emails, or returns the dependency a constructor refused.
func NewScheduler(cfg *config.Config, pool *pgxpool.Pool) (Scheduler, error) {
	organizations := newOrganizationRepository(cfg, pool)
	billingService, err := NewBillingService(cfg, pool, organizations)
	if err != nil {
		return Scheduler{}, err
	}
	plans, err := entitlements.NewService(planResolver(billingService, organizations))
	if err != nil {
		return Scheduler{}, fmt.Errorf("entitlements service: %w", err)
	}
	brandingRepo, err := newBrandingRepository(pool, plans, cfg.PublicBaseURL)
	if err != nil {
		return Scheduler{}, fmt.Errorf("branding repository: %w", err)
	}
	invoices, err := billing.NewInvoiceEmails(billingService, newMailer(cfg, pool, brandingRepo, email.NewService(pool)).sender, cfg.AppBaseURL)
	if err != nil {
		return Scheduler{}, fmt.Errorf("invoice emails: %w", err)
	}
	return Scheduler{Billing: billingService, Plans: plans, Invoices: invoices}, nil
}

// newOrganizationRepository returns the organization repository, creating
// every organization in the hosting region cfg names.
func newOrganizationRepository(cfg *config.Config, pool *pgxpool.Pool) *organization.Repository {
	return organization.NewRepository(pool, cmp.Or(cfg.HostingRegion, cfg.AWSRegion))
}

// BillingJobs returns billing's scheduled jobs: acting on subscriptions whose
// trial or period has ended, and emailing invoices.
func BillingJobs(svc *billing.Service, invoices *billing.InvoiceEmails) []worker.Scheduled {
	return []worker.Scheduled{
		{
			Name:     "billing-period-ends",
			Interval: billing.PeriodEndInterval,
			Run: func(ctx context.Context) error {
				run, err := svc.RunPeriodEnds(ctx)
				if run.Ended+run.Renewed+run.PastDue+run.Failed > 0 {
					slog.Info("subscription periods ended", "ended", run.Ended, "renewed", run.Renewed,
						"past_due", run.PastDue, "failed", run.Failed)
				}
				return err
			},
		},
		{
			Name:     "invoice-emails",
			Interval: billing.InvoiceEmailInterval,
			Run: func(ctx context.Context) error {
				n, err := invoices.Send(ctx)
				if n > 0 {
					slog.Info("invoices emailed", "sent", n)
				}
				return err
			},
		},
	}
}
