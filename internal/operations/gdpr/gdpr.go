// Package gdpr handles data-subject rights: erasure requests with a grace
// period, data exports, self-service account deletion and export, and the
// purge of a deleted organization's data. Erasure redacts PII in place, so
// audit references stay intact.
package gdpr

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// Service handles erasure and data-export requests; Run is its background
// sweeper. Until SetSessionSignals is called, ended sessions are not announced.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	grace    time.Duration
	workerID uuid.UUID
	lease    time.Duration
	signals  *sessionsignal.Signaller
}

// SetSessionSignals sets where the sessions an erasure ends are announced.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// NewService returns a Service whose erasure requests wait grace (30 days if
// grace <= 0) before the purge.
func NewService(pool *pgxpool.Pool, grace time.Duration) *Service {
	if grace <= 0 {
		grace = 30 * 24 * time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), grace: grace, workerID: uuid.New(), lease: 15 * time.Minute}
}

// userBelongsToOrganization reports whether organizationID is the user's home organization
// (users.organization_id), not merely one where the user holds a role. Erasure is
// irreversible, so only the owning organization may order it.
func (s *Service) userBelongsToOrganization(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.q.UserBelongsToOrganization(ctx, dbgen.UserBelongsToOrganizationParams{UserID: userID, OrganizationID: organizationID})
}

// recordSweep records, in tx, the background sweep finishing organizationID's data
// request requestID about userID.
func recordSweep(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, action, resourceType string, requestID, userID uuid.UUID) error {
	return audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, action, resourceType, requestID,
		map[string]any{"user_id": userID}))
}

// Run is the background sweeper. Every minute until ctx is done, it erases the
// users whose grace period has ended and builds pending data exports.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.tick(ctx); err != nil {
				slog.Warn("gdpr tick", "err", err)
			}
			if err := s.exportSweepTick(ctx); err != nil {
				slog.Warn("gdpr export tick", "err", err)
			}
		}
	}
}
