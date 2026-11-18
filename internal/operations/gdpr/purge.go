package gdpr

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// erasureFailures counts erasures the sweep could not carry out; each is
// retried once its lease runs out.
var erasureFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gdpr_erasure_failures_total",
	Help: "Erasure requests the background sweep failed to carry out (retried after their lease), such as the organization's last active owner.",
})

// Request is a right-to-erasure request.
type Request struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	UserID         uuid.UUID  `json:"user_id"`
	RequestedBy    *uuid.UUID `json:"requested_by"`
	Reason         *string    `json:"reason"`
	Status         string     `json:"status"`
	GraceUntil     time.Time  `json:"grace_until"`
	CompletedAt    *time.Time `json:"completed_at"`
	CreatedAt      time.Time  `json:"created_at"`
	// The person's email and name as the request was filed, until they are
	// erased; Redacted says they were.
	SubjectEmail *string `json:"subject_email"`
	SubjectName  *string `json:"subject_name"`
	Redacted     bool    `json:"subject_redacted"`
	// GraceDays is how long a request waits before the erasure runs.
	GraceDays int `json:"grace_period_days"`
}

// CreateInput is an erasure request to file.
type CreateInput struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         uuid.UUID `json:"user_id"`
	Reason         string    `json:"reason"`
}

// Request files an erasure request by actor, recorded as theirs, for a user
// whose home organization is in.OrganizationID; other users return errs.ErrNotFound. The
// purge runs once the grace period ends.
func (s *Service) Request(ctx context.Context, in CreateInput, actor audit.Actor) (*Request, error) {
	owned, err := s.userBelongsToOrganization(ctx, in.UserID, in.OrganizationID)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, errs.ErrNotFound
	}
	// grace_until is computed in Go rather than as NOW() + interval, whose sqlc
	// parameter type is ambiguous.
	var reason *string
	if in.Reason != "" {
		reason = &in.Reason
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).InsertPurgeRequest(ctx, dbgen.InsertPurgeRequestParams{
		OrganizationID: in.OrganizationID,
		SubjectID:      in.UserID,
		RequestedBy:    actor.UserID,
		Reason:         reason,
		GraceUntil:     time.Now().UTC().Add(s.grace),
	})
	if err != nil {
		return nil, err
	}
	req := purgeRequestFromRow(dbgen.ListPurgeRequestsRow(row))
	req.GraceDays = s.GraceDays()
	if err := audit.Record(ctx, tx, actor.Event(req.OrganizationID, "gdpr.erasure_requested", "purge_request", req.ID,
		map[string]any{"user_id": req.UserID, "grace_until": req.GraceUntil})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return req, nil
}

// Cancel cancels one of the organization's pending erasure requests, recorded as
// actor's. It returns errs.ErrNotFound if there is no such pending request.
func (s *Service) Cancel(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	userID, err := s.q.WithTx(tx).CancelPurgeRequest(ctx, dbgen.CancelPurgeRequestParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "gdpr.erasure_canceled", "purge_request", id,
		map[string]any{"user_id": userID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List returns the organization's 200 most recent erasure requests, newest first.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Request, error) {
	rows, err := s.q.ListPurgeRequests(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		req := purgeRequestFromRow(r)
		req.GraceDays = s.GraceDays()
		out = append(out, *req)
	}
	return out, nil
}

// GraceDays is how many days an erasure request waits before it runs.
func (s *Service) GraceDays() int { return int(s.grace / (24 * time.Hour)) }

// purgeRequestFromRow converts a purge-request row to a Request.
func purgeRequestFromRow(r dbgen.ListPurgeRequestsRow) *Request {
	return &Request{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		UserID:         r.SubjectID,
		RequestedBy:    r.RequestedBy,
		Reason:         r.Reason,
		Status:         r.Status,
		GraceUntil:     r.GraceUntil,
		CompletedAt:    r.CompletedAt,
		CreatedAt:      r.CreatedAt,
		SubjectEmail:   r.SubjectEmail,
		SubjectName:    r.SubjectName,
		Redacted:       r.Status == "completed",
	}
}

func (s *Service) tick(ctx context.Context) error {
	batch, err := s.q.LeaseDuePurgeRequests(ctx, dbgen.LeaseDuePurgeRequestsParams{
		LeaseOwner: s.workerID,
		LeaseUntil: time.Now().UTC().Add(s.lease),
	})
	if err != nil {
		return err
	}
	for _, e := range batch {
		if err := s.purgeOne(ctx, e.ID, e.SubjectID); err != nil {
			erasureFailures.Inc()
			slog.Warn("gdpr purge", "user", e.SubjectID, "err", err)
		}
	}
	return nil
}

// purgeOne erases the user of one leased request. If the user's home organization
// does not match the request's, the request is quarantined instead; if the
// account is already gone, the request is completed.
func (s *Service) purgeOne(ctx context.Context, requestID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	requestOrganization, err := q.LockLeasedPurgeRequest(ctx, dbgen.LockLeasedPurgeRequestParams{
		ID: requestID, SubjectID: userID, LeaseOwner: s.workerID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}

	userOrganization, err := q.LockAccountHome(ctx, userID)
	gone := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !gone {
		return err
	}
	if !gone && (userOrganization == nil || *userOrganization != requestOrganization) {
		if err := q.QuarantinePurgeRequest(ctx, dbgen.QuarantinePurgeRequestParams{ID: requestID, LeaseOwner: s.workerID}); err != nil {
			return err
		}
		if err := recordSweep(ctx, tx, requestOrganization, "gdpr.erasure_quarantined", "purge_request", requestID, userID); err != nil {
			return err
		}
		slog.Warn("gdpr purge quarantined", "request_id", requestID, "user_id", userID, "organization_id", requestOrganization)
		return tx.Commit(ctx)
	}

	if !gone {
		if err := s.eraseAccount(ctx, tx, userID); err != nil {
			return err
		}
	}
	n, err := q.CompletePurgeRequest(ctx, dbgen.CompletePurgeRequestParams{ID: requestID, LeaseOwner: s.workerID})
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("GDPR purge lease lost before completion")
	}
	if err := recordSweep(ctx, tx, requestOrganization, "gdpr.erasure_completed", "purge_request", requestID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PurgeSelf erases the current user's account at once, with no grace period,
// for self-service account deletion (see eraseAccount).
func (s *Service) PurgeSelf(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.eraseAccount(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
