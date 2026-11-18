package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

type namedWorker struct {
	name string
	run  worker.Func
}

// Services wires every service as the API does, for a tool that drives them
// directly, such as the development seed. No worker runs, nothing listens, and
// committed events wait in the outbox for the API's dispatcher.
func Services(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) Deps {
	depsCfg := *cfg
	depsCfg.NATSURL = ""
	deps, _ := buildDeps(ctx, &depsCfg, pool, outbox.LogPublisher{})
	return deps
}

// infra is the shared infrastructure every context's services are built from:
// configuration, keys, the outbound policy, the request verifier, the request
// limits and the outbound message chain. The chain dresses every message in
// the organization's branding and email templates, so brandingRepo and
// emailTemplateService are built with it; identity and operations serve them.
type infra struct {
	rootCtx              context.Context
	cfg                  *config.Config
	pool                 *pgxpool.Pool
	outboundPolicy       *egress.Policy
	sharedCipher         *envelope.Cipher
	signingKeyRegistry   *tokens.SigningKeyRegistry
	issuer               *tokens.Issuer
	verifier             *httpx.AuthVerifier
	brandingRepo         *branding.Repository
	emailTemplateService *email.Service
	mail                 mailer
	sender               notifier.Sender
	limits               rateLimits
	validate             *validator.Validate
	startedAt            time.Time
	healthHandler        *health.Handler
	inFlight             *httpx.InFlight
	// sessionSignals announces session and role changes over the webhook
	// dispatcher, so subscribers can react before access tokens expire. It is
	// set once the developer context's webhooks are built.
	sessionSignals *sessionsignal.Signaller
}

// newInfra builds the shared infrastructure, exiting when the keys, the
// outbound proxy or the rate-limit store can't be set up.
func newInfra(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) *infra {
	in := &infra{rootCtx: rootCtx, cfg: cfg, pool: pool, outboundPolicy: newOutboundPolicy(cfg)}
	keys := loadKeys(rootCtx, cfg, pool)
	in.sharedCipher, in.signingKeyRegistry, in.issuer = keys.cipher, keys.signingKeys, keys.issuer
	in.verifier = &httpx.AuthVerifier{
		Tokens:          in.issuer,
		DevTrustHeaders: cfg.AuthDevTrustHeaders,
	}
	in.brandingRepo = branding.NewRepository(pool)
	in.emailTemplateService = email.NewService(pool)
	in.mail = newMailer(cfg, pool, in.brandingRepo, in.emailTemplateService)
	in.sender = in.mail.sender
	in.limits = newRateLimits(rootCtx, cfg, pool)
	in.validate = newValidator()
	in.startedAt = time.Now()
	in.healthHandler = health.New(cfg.ServiceName, cfg.ServiceEnv, in.startedAt)
	in.healthHandler.ServiceProfile = cfg.ServiceProfile
	in.healthHandler.AddReadiness("db", health.PingDB(pool))
	in.healthHandler.AddReadiness("jwt-keyring", in.signingKeyRegistry.Ready) // not ready after repeated keyring refresh failures
	in.inFlight = httpx.NewInFlight()
	return in
}

// wiring is everything buildDeps builds: the shared infrastructure and each
// bounded context's services, which wire_<context>.go builds (new<Context>),
// connects to the rest (wire<Context>) and serves (<context>Handlers).
type wiring struct {
	*infra
	*accessServices
	*identityServices
	*federationServices
	*developerServices
	*operationsServices
}

// buildDeps constructs every repository, service, and handler and returns the
// HTTP dependency set plus the background workers to supervise. Keeping all
// wiring here lets main() focus on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, outboxPub outbox.Publisher) (Deps, []namedWorker) {
	w := &wiring{infra: newInfra(rootCtx, cfg, pool)}
	// Each context's services are built after those they are built from, then
	// every context is connected to the others.
	w.identityServices = w.newIdentity()
	w.accessServices = w.newAccess()
	w.operationsServices = w.newOperations()
	w.seedBuiltins()
	w.developerServices = w.newDeveloper()
	w.sessionSignals = sessionsignal.New(w.webhookService.EnqueueTx)
	w.federationServices = w.newFederation()
	w.wireVerifier()
	w.wireAccess()
	w.wireIdentity()
	w.wireFederation()
	w.wireDeveloper()
	w.wireOperations()

	deps := w.platformDeps()
	w.accessHandlers(&deps)
	w.identityHandlers(&deps)
	w.federationHandlers(&deps)
	w.developerHandlers(&deps)
	w.operationsHandlers(&deps)
	workers := w.workers(outboxPub)
	RegisterMaintenanceMetrics(pool, w.sharedCipher)
	return deps, workers
}

// seedBuiltins seeds the permission catalogue and the billing plans, exiting
// when either can't be seeded.
func (w *wiring) seedBuiltins() {
	if err := seedCatalogues(w.rootCtx, []namedSeeder{
		{"permission catalogue", w.rbacRepo.SeedBuiltins}, {"billing plans", w.billingService.SeedBuiltins},
	}); err != nil {
		slog.Error("start-up refused", "err", err)
		os.Exit(1)
	}
}

// wireVerifier lets the request verifier refuse at once the tokens of what has
// ended since they were issued.
func (w *wiring) wireVerifier() {
	// Let the auth middleware deny suspended/decommissioned agents' tokens per
	// request.
	w.verifier.AgentStatus = w.agentService.AgentStatus
	w.verifier.SessionUsed = w.authService.SessionUsed          // a session's last use, for its idle timeout and the session list
	w.verifier.SessionLive = w.authService.SessionLive          // an ended session's access tokens are refused at once
	w.verifier.PrincipalLive = w.principalService.PrincipalLive // a disabled service principal's tokens are refused at once
	w.verifier.APIKeyLive = w.apikeyService.Live                // an open activity stream's API key, checked again
}

// platformDeps is the router's shared middleware settings.
func (w *wiring) platformDeps() Deps {
	cfg := w.cfg
	return Deps{
		Health:       w.healthHandler,
		MetricsToken: cfg.MetricsToken,
		MetricsOpen:  cfg.IsDev(),
		InFlight:     w.inFlight,

		AuthVerifier:     w.verifier,
		AllowedOrigins:   cfg.AllowedOrigins(),
		ServiceName:      cfg.ServiceName,
		ServiceEnv:       cfg.ServiceEnv,
		StartedAt:        w.startedAt,
		CSRFDisabled:     cfg.CSRFDisabled,
		CSRFCookieDomain: cfg.CSRFCookieDomain,
		RateLimitStore:   w.limits.store,
		OrganizationLim:  w.limits.organization,
		UserLim:          w.limits.user,
		APIKeyLim:        w.limits.apiKey,
		Idempotency:      idempotency.NewStore(w.pool, w.sharedCipher),
	}
}

// workers are the background workers the API supervises.
func (w *wiring) workers(outboxPub outbox.Publisher) []namedWorker {
	cfg, pool := w.cfg, w.pool
	// Committed events reach the organization's webhook subscriptions as well
	// as the event stream.
	outboxDispatcher := outbox.NewDispatcher(pool, w.webhookService.Relay(outboxPub), 2*time.Second, 50)
	return []namedWorker{
		{name: "jwt-keyring", run: func(ctx context.Context) { w.signingKeyRegistry.Run(ctx, w.issuer, cfg.JWTSigningKeyRefreshInterval) }},
		// Each instance enforces the overrides from its own cache.
		{name: "rate-limit-overrides", run: func(ctx context.Context) {
			ratelimit.ReloadEvery(ctx, time.Minute, w.limits.organization, w.limits.user, w.limits.apiKey)
		}},
		{name: "authz-decision-log", run: w.decisionLog.Run}, // each instance writes the decisions it answered
		{name: "outbox", run: outboxDispatcher.Run},
		{name: "oidc-logout", run: w.oidcService.RunLogoutDeliveries},
		{name: "webhook", run: w.webhookService.RunDispatcher},
		{name: "gdpr", run: w.gdprService.Run},
		{name: "retention", run: w.retentionService.Run},
		{name: "siem", run: w.siemService.Run},
		{name: "audit-anomaly", run: w.auditAnomalyService.Run},
		// Audit-chain verification and the cleanups, once per interval across
		// instances.
		{name: "scheduler", run: func(ctx context.Context) {
			jobs := append(MaintenanceJobs(pool, w.sessionSignals, w.sharedCipher, w.outboundPolicy), BillingJobs(w.billingService)...)
			jobs = append(jobs, AccessRequestJobs(w.accessRequestService)...)
			jobs = append(jobs, AuditRetentionJobs(pool, w.billingService, w.sharedCipher)...)
			worker.RunScheduled(ctx, pool, jobs, worker.SchedulerTick)
		}},
	}
}

// namedSeeder seeds one built-in catalogue, named for the error that stops
// start-up when it can't.
type namedSeeder struct {
	name string
	seed func(ctx context.Context) error
}

// seedAttempts and seedRetryDelay bound how long start-up waits out a database
// that fails a seed, as one still starting up does.
var (
	seedAttempts   = 5
	seedRetryDelay = 2 * time.Second
)

// seedCatalogues seeds each catalogue, trying a failing one up to seedAttempts
// times, seedRetryDelay apart. One still failing is returned: a server without
// its permission catalogue or plans would answer every permission check and
// plan question from an empty one, so it must not start.
func seedCatalogues(ctx context.Context, seeders []namedSeeder) error {
	for _, s := range seeders {
		var err error
		for attempt := 1; attempt <= seedAttempts; attempt++ {
			if err = s.seed(ctx); err == nil {
				break
			}
			slog.Warn("seed a built-in catalogue", "catalogue", s.name, "attempt", attempt, "err", err)
			if attempt < seedAttempts {
				select {
				case <-ctx.Done():
					return fmt.Errorf("seed the %s: %w", s.name, ctx.Err())
				case <-time.After(seedRetryDelay):
				}
			}
		}
		if err != nil {
			return fmt.Errorf("seed the %s: %w", s.name, err)
		}
	}
	return nil
}
