package bootstrap

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// SchedulerAccessRequests is the access-request service the standalone
// scheduler sweeps with: RBAC with the API's webhook signal, and in-app
// notifications.
func SchedulerAccessRequests(pool *pgxpool.Pool) *accessrequest.Service {
	repo := rbac.NewRepository(pool)
	roles := rbac.NewService(repo)
	roles.SetEmitter(webhook.NewService(pool).Enqueue)
	svc := accessrequest.NewService(pool, roles, repo)
	svc.SetNotifier(notification.NewService(pool))
	return svc
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
