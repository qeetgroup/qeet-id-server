package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/operations/activity"
	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/critical"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/sales"
	"github.com/qeetgroup/qeet-id-server/internal/operations/search"
	"github.com/qeetgroup/qeet-id-server/internal/operations/servicehealth"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// operationsServices are the operations context's: billing and the plan's
// entitlements, audit, analytics, notifications, retention, GDPR, log
// streaming, Qeet AI, search and the activity stream. Its email templates are
// built with the shared message chain (newMailChain).
type operationsServices struct {
	billingService *billing.Service
	invoiceEmails  *billing.InvoiceEmails
	// entitlementSvc turns an organization's plan into feature flags and limits for the entitlements
	// endpoint and every plan check (as its limiter or gate); paid tiers resolve to unlimited or enabled,
	// so checks bite only where a plan caps.
	entitlementSvc      *entitlements.Service
	retentionService    *retention.Service
	salesService        *sales.Service
	notificationService *notification.Service
	siemService         *siem.Service // forwards audit events to configured log sinks
	qeetaiService       *qeetai.Service
	qeetaiProviderCfg   *qeetai.ProviderConfig
	// The Live Activity hub subscribes to NATS outbox events (when NATS_URL is
	// set) and fans them out to authenticated SSE connections filtered by
	// organization. Without NATS_URL it pushes no live events, and the stream
	// still connects and serves history and replay.
	activityNATSConn *nats.Conn
	activityHub      *activity.Hub
	// Universal search: a read-only fan-out across resource types, checking
	// each type's permission through the RBAC repository.
	searchService       *search.Service
	gdprService         *gdpr.Service
	auditReader         *audit.Reader
	auditVerifier       *audit.Verifier
	evidenceService     *compliance.EvidenceService
	auditAnomalyService *anomaly.Service
	analyticsReader     *analytics.Reader
	serviceHealth       *servicehealth.Service
}

// newOperationsBase builds the operations services every other context is
// built from: billing, the plans it resolves and in-app notifications.
func (w *wiring) newOperationsBase() (*operationsServices, error) {
	billingService, err := NewBillingService(w.cfg, w.pool, w.organizationRepo)
	if err != nil {
		return nil, err
	}
	entitlementSvc, err := entitlements.NewService(planResolver(billingService, w.organizationRepo))
	if err != nil {
		return nil, fmt.Errorf("entitlements service: %w", err)
	}
	return &operationsServices{
		billingService:      billingService,
		entitlementSvc:      entitlementSvc,
		notificationService: notification.NewService(w.pool),
	}, nil
}

// newOperations builds the rest of the operations context's services, once
// the message chain and the session signals exist.
func (w *wiring) newOperations() error {
	o := w.operationsServices
	var err error
	if o.invoiceEmails, err = billing.NewInvoiceEmails(o.billingService, w.sender, w.cfg.AppBaseURL); err != nil {
		return fmt.Errorf("invoice emails: %w", err)
	}
	if o.salesService, err = sales.NewService(w.pool, w.sender, w.cfg.SalesEmail); err != nil {
		return fmt.Errorf("sales service: %w", err)
	}
	if o.siemService, err = siem.NewService(w.pool, w.sharedCipher, w.outboundPolicy); err != nil {
		return fmt.Errorf("siem service: %w", err)
	}
	if o.qeetaiProviderCfg, err = newQeetaiProviderConfig(w.infra); err != nil {
		return fmt.Errorf("qeet ai provider config: %w", err)
	}
	if o.gdprService, err = gdpr.NewService(w.pool, 30*24*time.Hour, w.sessionSignals); err != nil {
		return fmt.Errorf("gdpr service: %w", err)
	}
	// Service health counts sign-in down while the signing keys can't be read.
	if o.serviceHealth, err = servicehealth.NewService(w.pool, w.signingKeyRegistry.Ready); err != nil {
		return fmt.Errorf("service health: %w", err)
	}
	o.retentionService = retention.NewService(w.pool)
	o.qeetaiService = qeetai.NewService(w.pool)
	o.activityNATSConn = connectActivityNATS(w.cfg)
	o.activityHub = activity.NewHub(o.activityNATSConn)
	o.searchService = search.NewService(w.pool, w.rbacRepo)
	o.auditReader = audit.NewReader(w.pool)
	o.auditVerifier = audit.NewVerifier(w.pool, w.sharedCipher)
	o.auditAnomalyService = anomaly.NewService(w.pool)
	o.analyticsReader = analytics.NewReader(w.pool)
	o.evidenceService = compliance.NewEvidenceService(w.pool, o.auditVerifier, w.cfg.BreachedPasswordCheck)
	return nil
}

// newQeetaiProviderConfig returns the Qeet AI provider config: per-organization
// keys, encrypted with the vault data key, with QEETAI_* as the platform
// fallback. The orchestrator is always built, since an organization can bring
// its own key.
func newQeetaiProviderConfig(in *infra) (*qeetai.ProviderConfig, error) {
	cfg := in.cfg
	qeetaiProviderCfg, err := qeetai.NewProviderConfig(in.pool, in.sharedCipher, qeetai.PlatformProvider{
		Provider:  cfg.QeetaiProvider,
		APIKey:    cfg.QeetaiAPIKey,
		Model:     cfg.QeetaiModel,
		BaseURL:   cfg.QeetaiBaseURL,
		MaxTokens: cfg.QeetaiMaxTokens,
	}, in.outboundPolicy)
	if err != nil {
		return nil, err
	}
	if qeetaiProviderCfg.PlatformConfigured() {
		slog.Info("Qeet AI: platform provider configured", "provider", cfg.QeetaiProvider, "model", cfg.QeetaiModel)
	} else {
		slog.Info("Qeet AI: no platform provider set — organizations must bring their own key (BYOK)")
	}
	return qeetaiProviderCfg, nil
}

// operationsHandlers serves the operations context.
func (w *wiring) operationsHandlers(d *Deps) error {
	if err := w.operationsCheckedHandlers(d); err != nil {
		return err
	}
	cfg := w.cfg
	d.Retention = &retention.Handler{Service: w.retentionService}
	d.EmailTemplate = &email.Handler{Service: w.emailTemplateService, Sender: w.sender, Appearance: w.brandingRepo, TestEmailEnabled: w.mail.testEnabled}
	d.EmailDelivery = &email.DeliveryHandler{Store: w.mail.deliveries}
	d.SESWebhook = &delivery.Webhook{Store: w.mail.deliveries, TopicARNs: cfg.SESEventsTopicARNs}
	d.Compliance = &compliance.Handler{Evidence: w.evidenceService}
	d.Audit = &audit.Handler{Reader: w.auditReader, Verifier: w.auditVerifier}
	d.AuditAnomaly = &anomaly.Handler{Service: w.auditAnomalyService}
	d.CriticalEvents = &critical.Handler{Service: critical.NewService(w.auditReader, w.auditAnomalyService)}
	d.Billing = &billing.Handler{Service: w.billingService}
	d.Sales = &sales.Handler{Service: w.salesService}
	d.Analytics = &analytics.Handler{Reader: w.analyticsReader}
	d.ServiceHealth = &servicehealth.Handler{Service: w.serviceHealth}
	d.RateLimits = &ratelimits.Handler{
		Pool:            w.pool,
		OrganizationLim: w.limits.organization,
		UserLim:         w.limits.user,
		APIKeyLim:       w.limits.apiKey,
		Defaults: ratelimits.Defaults{OrganizationRate: organizationLimitDefault.Rate, OrganizationCapacity: organizationLimitDefault.Capacity,
			UserRate: userLimitDefault.Rate, UserCapacity: userLimitDefault.Capacity,
			APIKeyRate: apiKeyLimitDefault.Rate, APIKeyCapacity: apiKeyLimitDefault.Capacity},
		BuiltIn: builtInLimits,
	}
	d.Notification = &notification.Handler{Service: w.notificationService}
	d.SIEM = &siem.Handler{Service: w.siemService}
	d.Search = &search.Handler{Service: w.searchService}
	d.endStreams = append(d.endStreams, w.activityHub.Shutdown)
	if w.activityNATSConn != nil {
		d.shutdownHooks = append(d.shutdownHooks, func() { _ = w.activityNATSConn.Drain() })
	}
	return nil
}

// operationsCheckedHandlers serves the operations handlers whose constructors
// refuse a missing check or source.
func (w *wiring) operationsCheckedHandlers(d *Deps) error {
	var err error
	if d.GDPR, err = gdpr.NewHandler(w.gdprService, w.authService, w.rbacRepo.CheckActOn); err != nil {
		return fmt.Errorf("gdpr handler: %w", err)
	}
	// Current usage for the billing usage-vs-limits display.
	if d.Entitlement, err = entitlements.NewHandler(w.entitlementSvc, entitlementUsageResolver{
		invites: w.inviteService, oidc: w.oidcService, apikeys: w.apikeyService, rbacRepo: w.rbacRepo, users: w.userRepo,
	}); err != nil {
		return fmt.Errorf("entitlements handler: %w", err)
	}
	if d.Qeetai, err = qeetai.NewHandler(qeetai.Handler{
		Service:      w.qeetaiService,
		Orchestrator: qeetai.NewOrchestrator(w.qeetaiProviderCfg, w.qeetaiService),
		Resolver:     w.qeetaiProviderCfg,
		Config:       w.qeetaiProviderCfg,
		Plan:         w.entitlementSvc, // platform fallback is a Pro+ feature; BYOK bypasses the gate
		Admin:        w.qeetaiService,
	}); err != nil {
		return fmt.Errorf("qeet ai handler: %w", err)
	}
	// An open activity stream is checked again as its request was admitted.
	if d.Activity, err = activity.NewHandler(w.pool, w.activityHub,
		streamAccess(w.verifier, w.decider, RoutePolicies()["GET /v1/activity/stream"])); err != nil {
		return fmt.Errorf("activity handler: %w", err)
	}
	return nil
}

// operationsPolicies are the operations context's routes whose policy is
// neither a permission nor user-only: search checks each result type's
// permission in its service, so it stays user-only until an equivalent
// per-type machine-scope evaluator exists.
func operationsPolicies() map[string]rbac.RoutePolicy {
	return map[string]rbac.RoutePolicy{
		"GET /v1/search": rbac.UserOnlyPolicy("user.read"),
	}
}

// auditChainVerifyJob verifies every audit chain with verifier.
func auditChainVerifyJob(verifier *audit.Verifier) worker.Scheduled {
	return worker.Scheduled{
		Name:     "audit-chain-verify",
		Interval: AuditVerifyInterval,
		Run: func(ctx context.Context) error {
			run, err := verifier.VerifyAll(ctx)
			if err == nil {
				slog.Info("audit chains intact", "scope", run.Scope, "organizations", run.OrganizationsWalked, "rows_checked", run.RowsChecked)
			}
			return err
		},
	}
}

// signInStateCleanupJob removes spent sign-in links, codes and requests, and
// stale failure counters (retention.SignInSweeps).
func signInStateCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "sign-in-state-cleanup",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			return runSweeps(ctx, pool, "sign-in state cleaned", retention.SignInSweeps)
		},
	}
}

// recordCleanupJob removes deliveries, detections, events, notifications,
// invitations and application grants past their use (retention.RecordSweeps).
func recordCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "record-cleanup",
		Interval: 24 * time.Hour,
		Run: func(ctx context.Context) error {
			return runSweeps(ctx, pool, "records cleaned", retention.RecordSweeps)
		},
	}
}

// organizationPurgesJob purges a deleted organization's data once its restore
// window has passed, its people's accounts with it, leaving a record that it
// was, with purges, which announces the sessions it ends.
func organizationPurgesJob(purges *gdpr.Service) worker.Scheduled {
	return worker.Scheduled{
		Name:     "organization-purges",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			n, err := purges.PurgeDeletedOrganizations(ctx, gdpr.OrganizationPurgeAfter)
			if n > 0 {
				slog.Info("deleted organizations purged", "purged", n)
			}
			return err
		},
	}
}

// qeetaiConversationRetentionJob deletes an organization's Qeet AI
// conversations once untouched for longer than it keeps them.
func qeetaiConversationRetentionJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "qeetai-conversation-retention",
		Interval: 24 * time.Hour,
		Run: func(ctx context.Context) error {
			n, err := qeetai.PurgeExpiredConversations(ctx, pool)
			if n > 0 {
				slog.Info("Qeet AI conversations purged", "deleted", n)
			}
			return err
		},
	}
}

// gdprExportExpiryJob deletes a built data export's payload, a full copy of
// the person's data, once its week of being downloadable is over.
func gdprExportExpiryJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "gdpr-export-expiry",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			n, err := gdpr.ExpireExports(ctx, pool, gdpr.ExportRetention)
			if err != nil {
				return err
			}
			slog.Info("data export payloads deleted", "expired", n)
			return nil
		},
	}
}

// emailDeliveryCleanupJob deletes email delivery records after 90 days:
// they answer "did that invitation arrive?", and after that nothing.
// Suppressions are kept.
func emailDeliveryCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "email-delivery-cleanup",
		Interval: 24 * time.Hour,
		Run: func(ctx context.Context) error {
			n, err := delivery.NewStore(pool).DeleteBefore(ctx, time.Now().Add(-delivery.Retention))
			if err != nil {
				return err
			}
			slog.Info("email delivery records cleaned", "deleted", n)
			return nil
		},
	}
}

// operationsPermissions are the operations context's routes and the user permission
// each needs, as userPermissionMap lists them.
func operationsPermissions() map[string]string {
	return map[string]string{
		// Qeet AI provider config (BYOK) — org owner/admin only. Reuses the
		// secrets permission so a newly added capability need not be backfilled
		// onto existing owner roles. The other /qeetai/* routes are user-level.
		"GET /v1/qeetai/provider-config":                         "secret.read",
		"PUT /v1/qeetai/provider-config":                         "secret.write",
		"DELETE /v1/qeetai/provider-config":                      "secret.write",
		"POST /v1/qeetai/provider-config/test":                   "secret.write",
		"GET /v1/organizations/{organizationID}/qeetai/usage":    "secret.read",
		"GET /v1/organizations/{organizationID}/qeetai/settings": "secret.read",
		"PUT /v1/organizations/{organizationID}/qeetai/settings": "secret.write",

		// Email templates.
		"PUT /v1/organizations/{organizationID}/email-templates/{key}":          "branding.write",
		"DELETE /v1/organizations/{organizationID}/email-templates/{key}":       "branding.write",
		"POST /v1/organizations/{organizationID}/email-templates/{key}/preview": "branding.write",
		"POST /v1/organizations/{organizationID}/email-templates/{key}/test":    "branding.write",
		"GET /v1/organizations/{organizationID}/email-templates":                "branding.write",
		"GET /v1/organizations/{organizationID}/email-templates/{key}":          "branding.write",

		// Retention and rate limits.
		"GET /v1/organizations/{organizationID}/retention":          "policy.read",
		"PUT /v1/organizations/{organizationID}/retention":          "policy.write",
		"POST /v1/organizations/{organizationID}/retention/preview": "policy.read",
		"POST /v1/organizations/{organizationID}/retention/run":     "policy.write",
		"GET /v1/organizations/{organizationID}/rate-limits":        "policy.read",
		"PUT /v1/organizations/{organizationID}/rate-limits":        "policy.write",
		"DELETE /v1/organizations/{organizationID}/rate-limits":     "policy.write",

		// GDPR.
		"POST /v1/gdpr/purge":                                                             "gdpr.write",
		"GET /v1/organizations/{organizationID}/gdpr/purge":                               "gdpr.write",
		"DELETE /v1/gdpr/purge/{id}":                                                      "gdpr.write",
		"POST /v1/gdpr/export":                                                            "gdpr.write",
		"GET /v1/organizations/{organizationID}/gdpr/export":                              "gdpr.write",
		"GET /v1/organizations/{organizationID}/gdpr/export/{id}":                         "gdpr.write",
		"POST /v1/organizations/{organizationID}/compliance/{framework}/evidence":         "audit.write",
		"GET /v1/organizations/{organizationID}/compliance/{framework}/evidence":          "audit.read",
		"GET /v1/organizations/{organizationID}/compliance/evidence/{id}":                 "audit.read",
		"GET /v1/organizations/{organizationID}/compliance/controls/owners":               "audit.read",
		"PUT /v1/organizations/{organizationID}/compliance/controls/{controlID}/owner":    "audit.write",
		"DELETE /v1/organizations/{organizationID}/compliance/controls/{controlID}/owner": "audit.write",
		"GET /v1/organizations/{organizationID}/compliance/audits":                        "audit.read",
		"POST /v1/organizations/{organizationID}/compliance/audits":                       "audit.write",
		"DELETE /v1/organizations/{organizationID}/compliance/audits/{id}":                "audit.write",

		// Audit (sensitive read).
		"GET /v1/organizations/{organizationID}/audit":              "audit.read",
		"GET /v1/organizations/{organizationID}/critical-events":    "audit.read",
		"GET /v1/organizations/{organizationID}/audit/verify":       "audit.read",
		"GET /v1/organizations/{organizationID}/audit/verification": "audit.read",

		// Live Activity feed — sourced from the audit log; same sensitivity.
		"GET /v1/activity":                                     "audit.read",
		"GET /v1/activity/summary":                             "audit.read",
		"GET /v1/activity/stream":                              "audit.read",
		"GET /v1/activity/{id}/related":                        "audit.read",
		"GET /v1/organizations/{organizationID}/activity/{id}": "audit.read",

		// Audit intelligence: behavioral-baseline anomaly detection over audit.events.
		"GET /v1/organizations/{organizationID}/audit/anomalies":               "audit.read",
		"GET /v1/organizations/{organizationID}/audit/anomalies/summary":       "audit.read",
		"POST /v1/organizations/{organizationID}/audit/anomalies/{id}/resolve": "audit.write",
		"GET /v1/organizations/{organizationID}/audit/anomaly-settings":        "audit.read",
		"PUT /v1/organizations/{organizationID}/audit/anomaly-settings":        "audit.write",

		// Billing. GET /v1/billing/plans is the catalogue: any signed-in person may
		// read it, with no permission, but it is a person's route (user-only, below).
		"GET /v1/organizations/{organizationID}/billing/subscription":              "billing.read",
		"PUT /v1/organizations/{organizationID}/billing/subscription":              "billing.write",
		"POST /v1/organizations/{organizationID}/billing/subscription/cancel":      "billing.write",
		"GET /v1/organizations/{organizationID}/billing/invoices":                  "billing.read",
		"POST /v1/organizations/{organizationID}/billing/invoices/{invoiceID}/pay": "billing.write",
		"GET /v1/organizations/{organizationID}/billing/payment-method":            "billing.read",
		"GET /v1/organizations/{organizationID}/billing/profile":                   "billing.read",
		"PUT /v1/organizations/{organizationID}/billing/profile":                   "billing.write",
		"POST /v1/organizations/{organizationID}/billing/trial":                    "billing.write",
		"POST /v1/organizations/{organizationID}/billing/checkout":                 "billing.write",
		"GET /v1/organizations/{organizationID}/entitlements":                      "billing.read",
		"GET /v1/organizations/{organizationID}/entitlements/usage":                "billing.read",

		// Analytics.
		"GET /v1/organizations/{organizationID}/analytics/overview": "analytics.read",
		"GET /v1/organizations/{organizationID}/service-health":     "organization.read",

		// Email delivery: whether the organization's mail arrived (support),
		// and lifting a suppression its mail caused (administrators).
		"GET /v1/organizations/{organizationID}/email/messages":             "user.read",
		"GET /v1/organizations/{organizationID}/email/suppressions":         "user.read",
		"DELETE /v1/organizations/{organizationID}/email/suppressions/{id}": "user.write",

		// SIEM/log streaming contains organization audit data.
		"GET /v1/organizations/{organizationID}/log-sinks":            "audit.read",
		"POST /v1/organizations/{organizationID}/log-sinks":           "audit.write",
		"PATCH /v1/organizations/{organizationID}/log-sinks/{id}":     "audit.write",
		"DELETE /v1/organizations/{organizationID}/log-sinks/{id}":    "audit.write",
		"POST /v1/organizations/{organizationID}/log-sinks/test":      "audit.write",
		"POST /v1/organizations/{organizationID}/log-sinks/{id}/test": "audit.write",
	}
}

// operationsUserOnlyRoutes are the operations context's routes of a person's own account or
// resources, which RoutePolicies makes user-only.
func operationsUserOnlyRoutes() []string {
	return []string{
		"GET /v1/notifications",
		"POST /v1/notifications/mark-all-read",
		"POST /v1/account/export",
		"POST /v1/account/delete",
		"GET /v1/billing/plans",
		"POST /v1/signup/checkout",
		"GET /v1/qeetai/status",
		"POST /v1/qeetai/conversations",
		"GET /v1/qeetai/conversations",
		"GET /v1/qeetai/conversations/{conversationID}",
		"PATCH /v1/qeetai/conversations/{conversationID}",
		"DELETE /v1/qeetai/conversations/{conversationID}",
		"POST /v1/qeetai/conversations/{conversationID}/messages",
		"POST /v1/sales/leads",
	}
}

// operationsStepUps are the operations context's routes that need a recent step-up, as
// StepUpRoutes lists them.
func operationsStepUps() map[string]mfa.StepUpRule {
	return stepUps(
		[]string{
			// Deleting the person's own account.
			"POST /v1/account/delete",
		},
		[]string{
			// The Qeet AI provider key, and the organization's rate limits.
			"PUT /v1/qeetai/provider-config",
			"DELETE /v1/qeetai/provider-config",
			"PUT /v1/organizations/{organizationID}/rate-limits",
			"DELETE /v1/organizations/{organizationID}/rate-limits",

			// Email the organization sends in its name.
			"PUT /v1/organizations/{organizationID}/email-templates/{key}",
			"DELETE /v1/organizations/{organizationID}/email-templates/{key}",

			// Retention and audit streaming.
			"PUT /v1/organizations/{organizationID}/retention",
			"POST /v1/organizations/{organizationID}/retention/run",
			"PUT /v1/organizations/{organizationID}/audit/anomaly-settings",
			"POST /v1/organizations/{organizationID}/log-sinks",
			"PATCH /v1/organizations/{organizationID}/log-sinks/{id}",
			"DELETE /v1/organizations/{organizationID}/log-sinks/{id}",
			"POST /v1/organizations/{organizationID}/log-sinks/test",
			"POST /v1/organizations/{organizationID}/log-sinks/{id}/test",

			// Erasing a person's data.
			"POST /v1/gdpr/purge",
		},
	)
}
