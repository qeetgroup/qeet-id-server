package bootstrap

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// NewBillingService returns the billing service cfg configures: card providers
// routed by billing country, invoice-only billing, tax and the payment grace.
// organizations creates a paid signup's organization. It emails nothing until
// SetMailer is called.
func NewBillingService(cfg *config.Config, pool *pgxpool.Pool, organizations *organization.Repository) *billing.Service {
	svc := billing.NewService(pool)
	payments := billing.NewPayments(
		cfg.StripeSecretKey, cfg.StripeWebhookSecret,
		cfg.RazorpayKeyID, cfg.RazorpayKeySecret, cfg.RazorpayWebhookSecret,
	).WithRouting(cfg.PaymentDefaultProvider, billing.ParseCountryRoutes(cfg.PaymentCountryRoutes)) // card payments (Stripe/Razorpay), routed by billing country; no-op until keys are configured
	if cfg.PaymentSandbox {
		payments = payments.WithSandbox(cfg.PaymentSandboxBaseURL, "sandbox-dev-secret") // dev-only fake provider; config.Validate refuses it outside dev
	}
	svc.SetPayments(payments)
	svc.SetAllowUnpaidActivation(cfg.BillingAllowUnpaidActivation)             // else a paid plan with no provider is refused, not granted free
	svc.SetOrgProvisioner(billingOrgProvisioner{organizations: organizations}) // creates the org when a signup checkout is paid
	svc.SetPaymentGrace(cfg.BillingPaymentGrace)                               // how long a renewal may go unpaid
	svc.SetTaxConfig(billing.TaxConfig{                                        // invoice GST/VAT (off unless configured)
		Enabled:       cfg.BillingTaxEnabled,
		SellerCountry: cfg.BillingSellerCountry,
		SellerState:   cfg.BillingSellerState,
		GSTRateBps:    cfg.BillingGSTRateBps,
		SupplierGSTIN: cfg.BillingSupplierGSTIN,
		SAC:           cfg.BillingSAC,
	})
	return svc
}

// SchedulerBilling is the billing service for the standalone scheduler, with
// its own outbound mail chain.
func SchedulerBilling(cfg *config.Config, pool *pgxpool.Pool) *billing.Service {
	svc := NewBillingService(cfg, pool, organization.NewRepository(pool))
	svc.SetMailer(newMailer(cfg, pool, branding.NewRepository(pool), email.NewService(pool)).sender, cfg.AppBaseURL)
	return svc
}

// BillingJobs returns billing's scheduled jobs: acting on subscriptions whose
// trial or period has ended, and emailing invoices.
func BillingJobs(svc *billing.Service) []worker.Scheduled {
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
				n, err := svc.SendInvoiceEmails(ctx)
				if n > 0 {
					slog.Info("invoices emailed", "sent", n)
				}
				return err
			},
		},
	}
}
