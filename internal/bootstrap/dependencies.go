package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
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
func Services(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) (Deps, error) {
	depsCfg := *cfg
	depsCfg.NATSURL = ""
	deps, _, err := buildDeps(ctx, &depsCfg, pool, outbox.LogPublisher{})
	return deps, err
}

// infra is the shared infrastructure every context's services are built from:
// configuration, keys, the outbound policy, the request limits, then the
// outbound message chain (newMailChain), the session signals and the request
// verifier (newVerifier) once what they are built from exists.
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
	// queue, so subscribers can react before access tokens expire.
	sessionSignals *sessionsignal.Signaller
}

// newInfra builds the shared infrastructure, exiting when the keys, the
// outbound proxy or the rate-limit store can't be set up.
func newInfra(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) *infra {
	in := &infra{rootCtx: rootCtx, cfg: cfg, pool: pool, outboundPolicy: newOutboundPolicy(cfg)}
	keys := loadKeys(rootCtx, cfg, pool)
	in.sharedCipher, in.signingKeyRegistry, in.issuer = keys.cipher, keys.signingKeys, keys.issuer
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
// HTTP dependency set plus the background workers to supervise, or the first
// dependency a constructor refused. Keeping all wiring here lets main() focus
// on process lifecycle.
func buildDeps(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, outboxPub outbox.Publisher) (Deps, []namedWorker, error) {
	w := &wiring{infra: newInfra(rootCtx, cfg, pool)}
	if err := w.build(); err != nil {
		return Deps{}, nil, err
	}
	deps := w.platformDeps()
	for _, serve := range []func(*Deps) error{
		w.accessHandlers, w.identityHandlers, w.federationHandlers, w.developerHandlers, w.operationsHandlers,
	} {
		if err := serve(&deps); err != nil {
			return Deps{}, nil, err
		}
	}
	workers, err := w.workers(outboxPub)
	if err != nil {
		return Deps{}, nil, err
	}
	RegisterMaintenanceMetrics(pool, w.sharedCipher)
	return deps, workers, nil
}

// build builds each context's services after those they depend on: repositories, billing's plans and
// notifications first (the message chain and every context need them), then the webhooks that carry
// the session signals, and the request verifier last, since it asks the services that end sessions.
func (w *wiring) build() error {
	var err error
	if err = w.newDirectories(); err != nil {
		return err
	}
	if w.operationsServices, err = w.newOperationsBase(); err != nil {
		return err
	}
	if err = w.newMailChain(); err != nil {
		return err
	}
	if err = w.seedBuiltins(); err != nil {
		return err
	}
	if w.developerServices, err = w.newDeveloper(); err != nil {
		return err
	}
	w.sessionSignals = sessionsignal.New(w.webhookService.EnqueueTx)
	if err = w.newOperations(); err != nil {
		return err
	}
	if err = w.newIdentity(); err != nil {
		return err
	}
	if err = w.newAccess(); err != nil {
		return err
	}
	if w.federationServices, err = w.newFederation(); err != nil {
		return err
	}
	return w.newVerifier()
}

// seedBuiltins seeds the permission catalogue and the billing plans.
func (w *wiring) seedBuiltins() error {
	return seedCatalogues(w.rootCtx, []namedSeeder{
		{"permission catalogue", w.rbacRepo.SeedBuiltins}, {"billing plans", w.billingService.SeedBuiltins},
	})
}

// newVerifier builds the request verifier, which refuses at once the tokens of
// what has ended since they were issued.
func (w *wiring) newVerifier() error {
	verifier, err := httpx.NewAuthVerifier(httpx.AuthVerifier{
		Tokens:          w.issuer,
		DevTrustHeaders: w.cfg.AuthDevTrustHeaders,
		AgentStatus:     w.agentService.AgentStatus,       // a suspended or decommissioned agent's tokens are refused
		SessionUsed:     w.authService.SessionUsed,        // a session's last use, for its idle timeout and the session list
		SessionLive:     w.authService.SessionLive,        // an ended session's access tokens are refused at once
		PrincipalLive:   w.principalService.PrincipalLive, // a disabled service principal's tokens are refused at once
		APIKeyLive:      w.apikeyService.Live,             // an open activity stream's API key, checked again
	})
	if err != nil {
		return fmt.Errorf("request verifier: %w", err)
	}
	w.verifier = verifier
	return nil
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
func (w *wiring) workers(outboxPub outbox.Publisher) ([]namedWorker, error) {
	cfg, pool := w.cfg, w.pool
	// Audit-chain verification and the cleanups, once per interval across
	// instances.
	jobs, err := MaintenanceJobs(pool, w.sessionSignals, w.sharedCipher, w.outboundPolicy)
	if err != nil {
		return nil, err
	}
	jobs = append(jobs, BillingJobs(w.billingService, w.invoiceEmails)...)
	jobs = append(jobs, AccessRequestJobs(w.accessRequestService)...)
	jobs = append(jobs, AuditRetentionJobs(pool, w.entitlementSvc, w.sharedCipher)...)
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
		{name: "scheduler", run: func(ctx context.Context) { worker.RunScheduled(ctx, pool, jobs, worker.SchedulerTick) }},
	}, nil
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
