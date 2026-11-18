package bootstrap

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// SchedulerAccessRequests is the access-request service the standalone scheduler sweeps with: RBAC
// announcing ended sessions (signals) and role changes (emitter), seats capped by billingService's
// plans, and in-app notifications, but no phone pushes.
func SchedulerAccessRequests(pool *pgxpool.Pool, signals *sessionsignal.Signaller, billingService *billing.Service,
	emitter rbac.EventEmitter, notifier notification.Notifier) (*accessrequest.Service, error) {
	plans, err := entitlements.NewService(planResolver(billingService, organization.NewRepository(pool, "")))
	if err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	repo := rbac.NewRepository(pool)
	seats, err := invite.NewSeats(pool, plans)
	if err != nil {
		return nil, fmt.Errorf("seats: %w", err)
	}
	roles, err := rbac.NewService(repo, rbac.ServiceDeps{Emitter: emitter, Limits: plans, Seats: seats, Signals: signals})
	if err != nil {
		return nil, fmt.Errorf("roles: %w", err)
	}
	svc, err := accessrequest.NewService(pool, roles, repo, notifier, accessrequest.NoPhones{})
	if err != nil {
		return nil, fmt.Errorf("access requests: %w", err)
	}
	return svc, nil
}

// AccessRequestJobs returns the access-request sweep: requests nobody answered
// in time lapse, and time-limited roles are taken back when their time is up.
func AccessRequestJobs(svc *accessrequest.Service) []worker.Scheduled {
	return []worker.Scheduled{{
		Name:     "access-request-sweep",
		Interval: accessrequest.SweepInterval,
		Run: func(ctx context.Context) error {
			res, err := svc.Sweep(postgres.AcrossOrganizations(ctx))
			if res.Lapsed+res.Ended+res.Failed > 0 {
				slog.Info("access requests swept", "lapsed", res.Lapsed, "ended", res.Ended, "failed", res.Failed)
			}
			return err
		},
	}}
}
