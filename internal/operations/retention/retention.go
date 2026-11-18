// Package retention enforces per-organization data-retention policy. Currently it
// permanently purges soft-deleted users once they're older than the organization's
// retention window. It is opt-in per organization (disabled by default) so the
// background sweeper never deletes data an organization hasn't explicitly allowed.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention/dbgen"
)

const sweepInterval = time.Hour

// Policy is an organization's retention policy.
// UpdatedAt and UpdatedBy say when, and by whom, it was last changed; nil
// until the organization sets one.
type Policy struct {
	DeletedUsersEnabled bool       `json:"deleted_users_enabled"`
	DeletedUsersDays    int        `json:"deleted_users_days"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
	UpdatedBy           *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedByEmail      *string    `json:"updated_by_email,omitempty"`
}

// DefaultPolicy is the policy of an organization that has set none.
func DefaultPolicy() Policy { return Policy{DeletedUsersEnabled: false, DeletedUsersDays: 30} }

func clampDays(d int) int {
	if d < 1 {
		return 1
	}
	if d > 3650 {
		return 3650
	}
	return d
}

// Service stores each organization's retention policy and enforces it.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the retention policy service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Get returns the organization's retention policy.
func (s *Service) Get(ctx context.Context, organizationID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetRetentionPolicy(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Policy{
		DeletedUsersEnabled: row.DeletedUsersEnabled,
		DeletedUsersDays:    int(row.DeletedUsersDays),
		UpdatedAt:           &row.UpdatedAt,
		UpdatedByEmail:      row.UpdatedByEmail,
	}
	p.UpdatedBy = row.UpdatedBy
	return p, nil
}

// Update stores the organization's retention policy, as changed by actor and
// recorded as theirs in the same transaction.
func (s *Service) Update(ctx context.Context, organizationID uuid.UUID, p Policy, actor audit.Actor) (*Policy, error) {
	p.DeletedUsersDays = clampDays(p.DeletedUsersDays)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).UpsertRetentionPolicy(ctx, dbgen.UpsertRetentionPolicyParams{
		OrganizationID:      organizationID,
		DeletedUsersEnabled: p.DeletedUsersEnabled,
		DeletedUsersDays:    int32(p.DeletedUsersDays), // #nosec G115 -- clamped to 1–3650 by clampDays
		UpdatedBy:           actor.UserID,
	})
	if err != nil {
		return nil, err
	}
	p.DeletedUsersEnabled = row.DeletedUsersEnabled
	p.DeletedUsersDays = int(row.DeletedUsersDays)
	p.UpdatedAt, p.UpdatedBy, p.UpdatedByEmail = &row.UpdatedAt, actor.UserID, nil
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "retention.policy_updated", "retention_policy", uuid.Nil,
		map[string]any{"deleted_users_enabled": p.DeletedUsersEnabled, "deleted_users_days": p.DeletedUsersDays})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

// RipeDeletedUsers counts soft-deleted users older than `days` for an organization —
// i.e. how many a purge would remove right now.
func (s *Service) RipeDeletedUsers(ctx context.Context, organizationID uuid.UUID, days int) (int, error) {
	// sqlc can't tell account.users.organization_id is NOT NULL here (the quoted
	// "user" schema), so the parameter is a pointer.
	n, err := s.q.CountRipeDeletedUsers(ctx, dbgen.CountRipeDeletedUsersParams{
		OrganizationID: &organizationID,
		Days:           int32(clampDays(days)), // #nosec G115 -- clamped to 1–3650 by clampDays
	})
	return int(n), err
}

// purgeListSize is how many ripe users PurgeOrganization lists at a time.
const purgeListSize = 500

// userPurgeFailures counts deleted accounts the purge could not remove.
var userPurgeFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "retention_user_purge_failures_total",
	Help: "Deleted accounts the retention purge failed to remove for good; each is tried again at the next run.",
})

// PurgeOrganization permanently deletes soft-deleted users past the window, one at
// a time, and returns the number purged. A user whose deletion fails is
// counted in retention_user_purge_failures_total and left for the next run;
// the others are still purged.
func (s *Service) PurgeOrganization(ctx context.Context, organizationID uuid.UUID, days int) (int, error) {
	organization := &organizationID  // see RipeDeletedUsers
	window := int32(clampDays(days)) // #nosec G115 -- clamped to 1–3650 by clampDays
	purged, after := 0, uuid.Nil
	for {
		ids, err := s.q.ListRipeDeletedUsers(ctx, dbgen.ListRipeDeletedUsersParams{
			OrganizationID: organization, Days: window, After: after, MaxRows: purgeListSize,
		})
		if err != nil {
			return purged, err
		}
		for _, id := range ids {
			n, err := s.q.PurgeRipeDeletedUser(ctx, dbgen.PurgeRipeDeletedUserParams{ID: id, OrganizationID: organization, Days: window})
			if ctx.Err() != nil {
				return purged, ctx.Err()
			}
			if err != nil {
				userPurgeFailures.Inc()
				slog.Warn("retention: purge a deleted user", "organization", organizationID, "user", id, "err", err)
				continue
			}
			purged += int(n)
		}
		if len(ids) < purgeListSize {
			return purged, nil
		}
		after = ids[len(ids)-1]
	}
}

// sweep purges ripe users for every organization that has the policy enabled.
func (s *Service) sweep(ctx context.Context) error {
	policies, err := s.q.ListEnabledRetentionPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		days := clampDays(int(p.DeletedUsersDays))
		n, err := s.PurgeOrganization(ctx, p.OrganizationID, days)
		if n > 0 {
			slog.Info("retention sweep purged users", "organization", p.OrganizationID, "count", n)
			if err := s.recordPurgeRun(ctx, p.OrganizationID, audit.Actor{Type: "system"}, n, days); err != nil {
				slog.Warn("retention sweep: record the purge", "organization", p.OrganizationID, "err", err)
			}
		}
		if err != nil {
			slog.Warn("retention sweep", "organization", p.OrganizationID, "err", err)
		}
	}
	return nil
}

// RunNow purges the organization's deleted users past its policy's window at
// once, as actor, and returns how many it purged. A run that purged anyone is
// recorded as actor's; failing to record it is logged, as the purge is done.
func (s *Service) RunNow(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) (int, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return 0, err
	}
	n, err := s.PurgeOrganization(ctx, organizationID, p.DeletedUsersDays)
	if err != nil {
		return n, err
	}
	if n > 0 {
		if err := s.recordPurgeRun(ctx, organizationID, actor, n, p.DeletedUsersDays); err != nil {
			slog.Warn("retention run: record the purge", "organization", organizationID, "err", err)
		}
	}
	return n, nil
}

// recordPurgeRun records in the organization's audit trail that a run by actor
// purged n deleted users older than days.
func (s *Service) recordPurgeRun(ctx context.Context, organizationID uuid.UUID, actor audit.Actor, n, days int) error {
	return audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "retention.purge_run", "retention_policy", uuid.Nil,
		map[string]any{"purged": n, "deleted_users_days": days}))
}

// Run is the background sweeper, registered as a worker. Only acts on organizations
// that have explicitly enabled retention.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(sweepInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.sweep(ctx); err != nil {
				slog.Warn("retention sweep", "err", err)
			}
		}
	}
}
