package bootstrap

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/logging"
)

// newOutboundPolicy returns the policy every outbound integration call goes
// through: public destinations only (any in dev), through EGRESS_PROXY_URL
// when set. It exits on a malformed proxy URL.
func newOutboundPolicy(cfg *config.Config) *egress.Policy {
	var egressProxy *url.URL
	if raw := strings.TrimSpace(cfg.EgressProxyURL); raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil {
			slog.Error("parse EGRESS_PROXY_URL", "err", err)
			os.Exit(1)
		}
		egressProxy = parsed
		slog.Info("outbound integrations routed through egress proxy", "host", egressProxy.Host)
	}
	outboundPolicy := egress.NewPolicy(egress.Options{ProxyURL: egressProxy})
	if cfg.IsDev() {
		outboundPolicy = egress.DevelopmentPolicy()
	}
	return outboundPolicy
}

// OutboundPolicy is the outbound policy the API uses, for the standalone
// scheduler's jobs.
func OutboundPolicy(cfg *config.Config) *egress.Policy { return newOutboundPolicy(cfg) }

// connectActivityNATS connects the Live Activity hub's subscriber to NATS_URL,
// returning nil when it is unset; the hub then serves history alone. It exits
// when the connection fails.
func connectActivityNATS(cfg *config.Config) *nats.Conn {
	var activityNATSConn *nats.Conn
	if cfg.NATSURL != "" {
		nc, err := nats.Connect(cfg.NATSURL,
			nats.Name("qeet-id-activity-sub"),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2*time.Second),
		)
		if err != nil {
			slog.Error("activity: connect nats subscriber", "err", err)
			os.Exit(1)
		}
		activityNATSConn = nc
		slog.Info("activity hub: connected to NATS", "url", logging.StripURLCredentials(cfg.NATSURL))
	}
	return activityNATSConn
}

// rateLimits are the request limiters: per organization, user and API key, with
// each organization's overrides, and the tighter magic-link limits.
type rateLimits struct {
	store                      ratelimit.Store // Redis, shared across replicas; nil keeps limits per instance
	organization, user, apiKey *ratelimit.OrganizationLimiter
	magicAddress, magicCaller  *ratelimit.Limiter
	resetAddress               *ratelimit.Limiter
}

// newRateLimits builds the limiters, exiting when REDIS_URL is set but
// unusable.
func newRateLimits(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) rateLimits {
	// Rate-limit store: Redis (shared across replicas) when REDIS_URL is set,
	// otherwise in-process. Required for correct limits when scaling out.
	var rlStore ratelimit.Store
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			slog.Error("parse REDIS_URL", "err", err)
			os.Exit(1)
		}
		rdb := redis.NewClient(opt)
		if err := rdb.Ping(rootCtx).Err(); err != nil {
			slog.Error("redis ping", "err", err)
			os.Exit(1)
		}
		rlStore = ratelimit.NewRedisStore(rdb)
		slog.Info("rate limiting via Redis (shared across replicas)")
	}

	// Build organization-aware limiters that allow per-organization rate overrides stored in DB.
	newOrganizationLim := func(def ratelimits.Bucket, key string) *ratelimit.OrganizationLimiter {
		var store ratelimit.Store
		if rlStore != nil {
			store = rlStore
		} else {
			store = ratelimit.NewMemStore()
		}
		lim := ratelimit.NewOrganizationLimiter(store, def.Rate, def.Capacity, pool, key)
		lim.LoadOverrides(rootCtx)
		return lim
	}
	// Magic-link requests are bounded more tightly than sign-in: three per
	// address, then one every five minutes; ten per caller, then one a minute.
	// Password-reset requests share the per-address bound.
	magicStore := rlStore
	if magicStore == nil {
		magicStore = ratelimit.NewMemStore()
	}
	return rateLimits{
		store:        rlStore,
		organization: newOrganizationLim(organizationLimitDefault, "tenant"),
		user:         newOrganizationLim(userLimitDefault, "user"),
		apiKey:       newOrganizationLim(apiKeyLimitDefault, "api_key"),
		magicAddress: ratelimit.NewWithStore(magicStore, magicAddressLimit.Rate, magicAddressLimit.Capacity),
		magicCaller:  ratelimit.NewWithStore(magicStore, magicCallerLimit.Rate, magicCallerLimit.Capacity),
		resetAddress: ratelimit.NewWithStore(magicStore, resetAddressLimit.Rate, resetAddressLimit.Capacity),
	}
}

// newValidator returns the request validator.
func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	// Use JSON field names in validation errors so the per-field messages the
	// API returns match the request body the client sent (e.g. "display_name",
	// not "DisplayName").
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	return v
}
