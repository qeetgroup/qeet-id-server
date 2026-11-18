package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ExportRetention is how long a built export's payload is kept for download.
// It is then deleted and the request marked expired.
const ExportRetention = 7 * 24 * time.Hour

// ExpireExports deletes the payloads of exports that became ready longer ago
// than retention, marking them expired, and returns how many. Run on a
// schedule.
func ExpireExports(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	q := dbgen.New(pool)
	cutoff := time.Now().UTC().Add(-retention)
	return postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.ExpireReadyExports(ctx, dbgen.ExpireReadyExportsParams{Cutoff: cutoff, MaxRows: limit})
	})
}

// ExportRequest is a data-export job. The background sweep (exportSweepTick)
// fills in Payload and sets Status to "ready".
type ExportRequest struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	UserID         uuid.UUID      `json:"user_id"`
	RequestedBy    *uuid.UUID     `json:"requested_by"`
	Status         string         `json:"status"`
	Payload        map[string]any `json:"payload,omitempty"`
	Error          *string        `json:"error,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at"`
	CreatedAt      time.Time      `json:"created_at"`
}

// ExportInput is a data-export request to queue.
type ExportInput struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         uuid.UUID `json:"user_id"`
}

// RequestExport queues a data export by actor, recorded as theirs, for a user
// whose home organization is in.OrganizationID. The background sweep builds it; poll
// GetExport for the result.
func (s *Service) RequestExport(ctx context.Context, in ExportInput, actor audit.Actor) (*ExportRequest, error) {
	owned, err := s.userBelongsToOrganization(ctx, in.UserID, in.OrganizationID)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, errs.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).InsertExportRequest(ctx, dbgen.InsertExportRequestParams{
		OrganizationID: in.OrganizationID,
		SubjectID:      in.UserID,
		RequestedBy:    actor.UserID,
	})
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(row.OrganizationID, "gdpr.export_requested", "export_request", row.ID,
		map[string]any{"user_id": row.SubjectID})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ExportRequest{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		UserID:         row.SubjectID,
		RequestedBy:    row.RequestedBy,
		Status:         row.Status,
		CompletedAt:    row.CompletedAt,
		CreatedAt:      row.CreatedAt,
	}, nil
}

// ListExports returns the organization's 200 most recent export requests, newest
// first, without payloads.
func (s *Service) ListExports(ctx context.Context, organizationID uuid.UUID) ([]ExportRequest, error) {
	rows, err := s.q.ListExportRequests(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]ExportRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExportRequest{
			ID:             r.ID,
			OrganizationID: r.OrganizationID,
			UserID:         r.SubjectID,
			RequestedBy:    r.RequestedBy,
			Status:         r.Status,
			Error:          r.Error,
			CompletedAt:    r.CompletedAt,
			CreatedAt:      r.CreatedAt,
		})
	}
	return out, nil
}

// GetExport returns one of the organization's export requests, with its payload once
// ready.
func (s *Service) GetExport(ctx context.Context, organizationID, id uuid.UUID) (*ExportRequest, error) {
	r, err := s.q.GetExportRequest(ctx, dbgen.GetExportRequestParams{
		ID:             id,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &ExportRequest{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		UserID:         r.SubjectID,
		RequestedBy:    r.RequestedBy,
		Status:         r.Status,
		Error:          r.Error,
		CompletedAt:    r.CompletedAt,
		CreatedAt:      r.CreatedAt,
	}
	if len(r.Payload) > 0 {
		if err := json.Unmarshal(r.Payload, &out.Payload); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// exportSweepTick leases up to 20 pending export requests and builds their
// payloads, marking a request "failed" if building it fails.
func (s *Service) exportSweepTick(ctx context.Context) error {
	batch, err := s.q.LeasePendingExportRequests(ctx, dbgen.LeasePendingExportRequestsParams{
		LeaseOwner: s.workerID,
		LeaseUntil: time.Now().UTC().Add(s.lease),
	})
	if err != nil {
		return err
	}
	for _, e := range batch {
		if err := s.buildExport(ctx, e.ID, e.OrganizationID, e.SubjectID); err != nil {
			slog.Warn("gdpr export", "user", e.SubjectID, "err", err)
			if err := s.failExport(ctx, e.ID, e.OrganizationID, e.SubjectID, err.Error()); err != nil {
				slog.Warn("gdpr export: mark failed", "request_id", e.ID, "err", err)
			}
		}
	}
	return nil
}

// buildExport stores the payload of a leased export request and marks it
// ready, recorded in the same transaction.
func (s *Service) buildExport(ctx context.Context, requestID, organizationID, userID uuid.UUID) error {
	payload, err := s.collectUserData(ctx, organizationID, userID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).CompleteExportRequest(ctx, dbgen.CompleteExportRequestParams{
		ID: requestID, LeaseOwner: s.workerID, Payload: raw,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("GDPR export lease lost before completion")
	}
	if err := recordSweep(ctx, tx, organizationID, "gdpr.export_completed", "export_request", requestID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// failExport marks a leased export request failed with msg, recorded in the
// same transaction. A request whose lease has passed to another worker is left
// alone.
func (s *Service) failExport(ctx context.Context, requestID, organizationID, userID uuid.UUID, msg string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).FailExportRequest(ctx, dbgen.FailExportRequestParams{
		ErrorMsg:       &msg,
		ID:             requestID,
		OrganizationID: organizationID,
		LeaseOwner:     &s.workerID,
	})
	if err != nil || n != 1 {
		return err
	}
	if err := recordSweep(ctx, tx, organizationID, "gdpr.export_failed", "export_request", requestID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
