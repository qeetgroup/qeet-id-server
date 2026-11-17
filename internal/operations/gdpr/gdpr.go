// Package gdpr handles data-subject rights: erasure requests with a grace
// period, data exports, self-service account deletion and export, and SOC 2 and
// ISO 27001 compliance evidence. Erasure redacts PII in place, so audit
// references stay intact.
package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// erasureFailures counts erasures the sweep could not carry out; each is
// retried once its lease runs out.
var erasureFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gdpr_erasure_failures_total",
	Help: "Erasure requests the background sweep failed to carry out (retried after their lease), such as the organisation's last active owner.",
})

// Request is a right-to-erasure request.
type Request struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"tenant_id"`
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

// endSessions ends every session of the account being erased and announces
// each one (reason deleted) in the erasure's transaction.
func (s *Service) endSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	if err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonDeleted, ended...)
	return nil
}

// NewService returns a Service whose erasure requests wait grace (30 days if
// grace <= 0) before the purge.
func NewService(pool *pgxpool.Pool, grace time.Duration) *Service {
	if grace <= 0 {
		grace = 30 * 24 * time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), grace: grace, workerID: uuid.New(), lease: 15 * time.Minute}
}

// CreateInput is an erasure request to file.
type CreateInput struct {
	OrganizationID uuid.UUID `json:"tenant_id"`
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
		RequestedBy:    pgUUIDNullable(actor.UserID),
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

// userBelongsToOrganization reports whether organizationID is the user's home organization
// (users.organization_id), not merely one where the user holds a role. Erasure is
// irreversible, so only the owning organization may order it.
func (s *Service) userBelongsToOrganization(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	var owned bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM account.users
			WHERE id = $1 AND organization_id = $2
		)
	`, userID, organizationID).Scan(&owned)
	return owned, err
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

// recordSweep records, in tx, the background sweep finishing organizationID's data
// request requestID about userID.
func recordSweep(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, action, resourceType string, requestID, userID uuid.UUID) error {
	return audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, action, resourceType, requestID,
		map[string]any{"user_id": userID}))
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
		RequestedBy:    toUUIDPtr(r.RequestedBy),
		Reason:         r.Reason,
		Status:         r.Status,
		GraceUntil:     r.GraceUntil,
		CompletedAt:    toTimePtr(r.CompletedAt),
		CreatedAt:      r.CreatedAt,
		SubjectEmail:   r.SubjectEmail,
		SubjectName:    r.SubjectName,
		Redacted:       r.Status == "completed",
	}
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

func (s *Service) tick(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT id
			FROM account.purge_requests
			WHERE status = 'pending' AND grace_until <= NOW()
			  AND (lease_until IS NULL OR lease_until <= NOW())
			ORDER BY grace_until, created_at
			LIMIT 50
			FOR UPDATE SKIP LOCKED
		)
		UPDATE account.purge_requests AS request
		SET lease_owner = $1, lease_until = $2
		FROM candidates
		WHERE request.id = candidates.id
		RETURNING request.id, request.subject_id
	`, s.workerID, time.Now().UTC().Add(s.lease))
	if err != nil {
		return err
	}
	type purgeJob struct{ ID, UserID uuid.UUID }
	var batch []purgeJob
	for rows.Next() {
		var job purgeJob
		if err := rows.Scan(&job.ID, &job.UserID); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, e := range batch {
		if err := s.purgeOne(ctx, e.ID, e.UserID); err != nil {
			erasureFailures.Inc()
			slog.Warn("gdpr purge", "user", e.UserID, "err", err)
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

	var requestOrganization uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT organization_id
		FROM account.purge_requests
		WHERE id = $1 AND subject_id = $2 AND status = 'pending' AND lease_owner = $3
		FOR UPDATE
	`, requestID, userID, s.workerID).Scan(&requestOrganization); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}

	var userOrganization *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT organization_id FROM account.users WHERE id = $1 FOR UPDATE
	`, userID).Scan(&userOrganization)
	gone := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !gone {
		return err
	}
	if !gone && (userOrganization == nil || *userOrganization != requestOrganization) {
		if _, err := tx.Exec(ctx, `
			UPDATE account.purge_requests
			SET status = 'quarantined', quarantined_at = NOW(),
			    quarantine_reason = 'tenant ownership mismatch detected by worker',
			    lease_owner = NULL, lease_until = NULL
			WHERE id = $1 AND status = 'pending' AND lease_owner = $2
		`, requestID, s.workerID); err != nil {
			return err
		}
		if err := recordSweep(ctx, tx, requestOrganization, "gdpr.erasure_quarantined", "purge_request", requestID, userID); err != nil {
			return err
		}
		slog.Warn("gdpr purge quarantined", "request_id", requestID, "user_id", userID, "tenant_id", requestOrganization)
		return tx.Commit(ctx)
	}

	if !gone {
		if err := s.eraseAccount(ctx, tx, userID); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE account.purge_requests
		SET status = 'completed', completed_at = NOW(), lease_owner = NULL, lease_until = NULL,
		    subject_email = NULL, subject_name = NULL
		WHERE id = $1 AND status = 'pending' AND lease_owner = $2
	`, requestID, s.workerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("GDPR purge lease lost before completion")
	}
	if err := recordSweep(ctx, tx, requestOrganization, "gdpr.erasure_completed", "purge_request", requestID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// eraseAccount ends the account's sessions, redacts its user row and deletes
// the rest of its data (see accountData and addressData), in tx. The redacted
// user row and the audit trail are kept, so past events stay verifiable. The
// caller has checked that the account may be erased.
func (s *Service) eraseAccount(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Sessions first, announced before anything about the account is redacted.
	if err := s.endSessions(ctx, tx, userID); err != nil {
		return err
	}
	email, err := dbgen.New(tx).PurgeUserPII(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	return eraseAccountData(ctx, tx, userID, email)
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

// ExportRequest is a data-export job. The background sweep (exportSweepTick)
// fills in Payload and sets Status to "ready".
type ExportRequest struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"tenant_id"`
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
	OrganizationID uuid.UUID `json:"tenant_id"`
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
		RequestedBy:    pgUUIDNullable(actor.UserID),
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
		RequestedBy:    toUUIDPtr(row.RequestedBy),
		Status:         row.Status,
		CompletedAt:    toTimePtr(row.CompletedAt),
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
			RequestedBy:    toUUIDPtr(r.RequestedBy),
			Status:         r.Status,
			Error:          r.Error,
			CompletedAt:    toTimePtr(r.CompletedAt),
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
		RequestedBy:    toUUIDPtr(r.RequestedBy),
		Status:         r.Status,
		Error:          r.Error,
		CompletedAt:    toTimePtr(r.CompletedAt),
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
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT id
			FROM account.export_requests
			WHERE status = 'pending' AND (lease_until IS NULL OR lease_until <= NOW())
			ORDER BY created_at
			LIMIT 20
			FOR UPDATE SKIP LOCKED
		)
		UPDATE account.export_requests AS request
		SET lease_owner = $1, lease_until = $2
		FROM candidates
		WHERE request.id = candidates.id
		RETURNING request.id, request.organization_id, request.subject_id
	`, s.workerID, time.Now().UTC().Add(s.lease))
	if err != nil {
		return err
	}
	type exportJob struct{ ID, OrganizationID, UserID uuid.UUID }
	var batch []exportJob
	for rows.Next() {
		var job exportJob
		if err := rows.Scan(&job.ID, &job.OrganizationID, &job.UserID); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, e := range batch {
		if err := s.buildExport(ctx, e.ID, e.OrganizationID, e.UserID); err != nil {
			slog.Warn("gdpr export", "user", e.UserID, "err", err)
			if err := s.failExport(ctx, e.ID, e.OrganizationID, e.UserID, err.Error()); err != nil {
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
	tag, err := tx.Exec(ctx, `
		UPDATE account.export_requests
		SET status = 'ready', payload = $3, completed_at = NOW(),
		    lease_owner = NULL, lease_until = NULL
		WHERE id = $1 AND lease_owner = $2
	`, requestID, s.workerID, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
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
		LeaseOwner:     pgUUIDNullable(&s.workerID),
	})
	if err != nil || n != 1 {
		return err
	}
	if err := recordSweep(ctx, tx, organizationID, "gdpr.export_failed", "export_request", requestID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type exportProfile struct {
	Email           string         `json:"email"`
	Phone           *string        `json:"phone,omitempty"`
	DisplayName     *string        `json:"display_name,omitempty"`
	AvatarURL       *string        `json:"avatar_url,omitempty"`
	Metadata        map[string]any `json:"metadata"`
	Status          string         `json:"status"`
	EmailVerifiedAt *time.Time     `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt *time.Time     `json:"phone_verified_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type exportSession struct {
	ID         uuid.UUID  `json:"id"`
	IP         *string    `json:"ip,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type exportPasskey struct {
	ID         uuid.UUID  `json:"id"`
	Name       *string    `json:"name,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type exportRole struct {
	RoleName  string    `json:"role_name"`
	GrantedAt time.Time `json:"granted_at"`
}

// collectUserData assembles one user's portable data in an organization: profile,
// sessions, passkeys, MFA status, roles and the sections of exportSections.
// Credentials (password hashes, TOTP secrets, recovery codes) are excluded.
func (s *Service) collectUserData(ctx context.Context, organizationID, userID uuid.UUID) (map[string]any, error) {
	// account.users.organization_id is nullable, so it takes a pgtype.UUID.
	profileRow, err := s.q.GetUserProfileForExport(ctx, dbgen.GetUserProfileForExportParams{
		UserID:         userID,
		OrganizationID: pgUUIDNullable(&organizationID),
	})
	if err != nil {
		return nil, err
	}
	profile := exportProfile{
		Email:           profileRow.Email,
		Phone:           profileRow.Phone,
		DisplayName:     profileRow.DisplayName,
		AvatarURL:       profileRow.AvatarUrl,
		Metadata:        metadataOf(profileRow.Metadata),
		Status:          profileRow.Status,
		EmailVerifiedAt: toTimePtr(profileRow.EmailVerifiedAt),
		PhoneVerifiedAt: toTimePtr(profileRow.PhoneVerifiedAt),
		CreatedAt:       profileRow.CreatedAt,
	}

	// auth.sessions.organization_id is nullable, so it takes a pgtype.UUID.
	sessRows, err := s.q.ListUserSessionsForExport(ctx, dbgen.ListUserSessionsForExportParams{
		UserID:         userID,
		OrganizationID: pgUUIDNullable(&organizationID),
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]exportSession, 0, len(sessRows))
	for _, r := range sessRows {
		// ip is COALESCE(host(ip), '') → interface{}; nil *string when empty.
		var ipPtr *string
		if ip, ok := r.Ip.(string); ok && ip != "" {
			ipPtr = &ip
		}
		sessions = append(sessions, exportSession{
			ID:         r.ID,
			IP:         ipPtr,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
			RevokedAt:  toTimePtr(r.RevokedAt),
		})
	}

	pkRows, err := s.q.ListUserPasskeysForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]exportPasskey, 0, len(pkRows))
	for _, r := range pkRows {
		passkeys = append(passkeys, exportPasskey{
			ID:         r.ID,
			Name:       r.Name,
			Transports: r.Transports,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: toTimePtr(r.LastUsedAt),
		})
	}

	roleRows, err := s.q.ListUserRolesForExport(ctx, dbgen.ListUserRolesForExportParams{
		UserID:         userID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	roles := make([]exportRole, 0, len(roleRows))
	for _, r := range roleRows {
		roles = append(roles, exportRole{RoleName: r.RoleName, GrantedAt: r.GrantedAt})
	}

	// ErrNoRows means no TOTP factor, so mfaEnabled stays false.
	mfaEnabled, err := s.q.GetUserMFAStatus(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	out := map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}
	if err := exportSections(ctx, s.q, userID, &organizationID, out); err != nil {
		return nil, err
	}
	return out, nil
}

type exportSelfRole struct {
	RoleName     string    `json:"role_name"`
	Organization string    `json:"organization"`
	GrantedAt    time.Time `json:"granted_at"`
}

// ExportSelf assembles the current user's portable data across all their
// organizations, with no organization scope: a self-service user may have no organization.
// Credentials are excluded.
func (s *Service) ExportSelf(ctx context.Context, userID uuid.UUID) (map[string]any, error) {
	var profile exportProfile
	var metadata []byte
	if err := s.pool.QueryRow(ctx, `
		SELECT email, phone, display_name, avatar_url, metadata, status, email_verified_at, phone_verified_at, created_at
		FROM account.users
		WHERE id = $1`, userID,
	).Scan(&profile.Email, &profile.Phone, &profile.DisplayName, &profile.AvatarURL, &metadata, &profile.Status,
		&profile.EmailVerifiedAt, &profile.PhoneVerifiedAt, &profile.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	profile.Metadata = metadataOf(metadata)

	sessRows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(host(ip), '') AS ip, user_agent, created_at, last_seen_at, revoked_at
		FROM auth.sessions
		WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer sessRows.Close()
	sessions := make([]exportSession, 0)
	for sessRows.Next() {
		var e exportSession
		var ip string
		if err := sessRows.Scan(&e.ID, &ip, &e.UserAgent, &e.CreatedAt, &e.LastSeenAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		if ip != "" {
			ipCopy := ip
			e.IP = &ipCopy
		}
		sessions = append(sessions, e)
	}
	if err := sessRows.Err(); err != nil {
		return nil, err
	}

	pkRows, err := s.q.ListUserPasskeysForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]exportPasskey, 0, len(pkRows))
	for _, r := range pkRows {
		passkeys = append(passkeys, exportPasskey{
			ID:         r.ID,
			Name:       r.Name,
			Transports: r.Transports,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: toTimePtr(r.LastUsedAt),
		})
	}

	roleRows, err := s.pool.Query(ctx, `
		SELECT r.name, t.name, ur.granted_at
		FROM rbac.user_roles ur
		JOIN rbac.roles r ON r.id = ur.role_id
		JOIN organization.organizations t ON t.id = ur.organization_id
		WHERE ur.user_id = $1
		ORDER BY ur.granted_at`, userID)
	if err != nil {
		return nil, err
	}
	defer roleRows.Close()
	roles := make([]exportSelfRole, 0)
	for roleRows.Next() {
		var role exportSelfRole
		if err := roleRows.Scan(&role.RoleName, &role.Organization, &role.GrantedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := roleRows.Err(); err != nil {
		return nil, err
	}

	// ErrNoRows means no TOTP factor, so mfaEnabled stays false.
	mfaEnabled, err := s.q.GetUserMFAStatus(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	out := map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}
	if err := exportSections(ctx, s.q, userID, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReauthChecker re-verifies a user's password before an irreversible action.
// hasPassword is false for an account without a password.
type ReauthChecker interface {
	ReauthPassword(ctx context.Context, userID uuid.UUID, plain string) (hasPassword, ok bool, err error)
}

// Handler serves the GDPR, self-service account and compliance evidence
// endpoints. Reauth, when set, makes account deletion require the password of
// an account that has one.
type Handler struct {
	Service  *Service
	Evidence *EvidenceService
	Reauth   ReauthChecker
	// ActOnCheck refuses an erasure or export of someone who outranks the
	// caller (rbac.Repository.CheckActOn), as deleting their account is
	// refused. Without it both are refused.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error
}

// Mount registers the routes.
func (h *Handler) Mount(r chi.Router) {
	// Self-service: the signed-in user acts on their own account, and no organization
	// is required.
	r.Post("/account/export", h.exportSelf)
	r.Post("/account/delete", h.deleteSelf)

	r.Post("/gdpr/purge", h.create)
	r.Get("/tenants/{tenantID}/gdpr/purge", h.list)
	r.Delete("/gdpr/purge/{id}", h.cancel)

	r.Post("/gdpr/export", h.createExport)
	r.Get("/tenants/{tenantID}/gdpr/export", h.listExports)
	r.Get("/tenants/{tenantID}/gdpr/export/{id}", h.getExport)

	// SOC 2 and ISO 27001 compliance evidence.
	h.mountEvidence(r)
}

// exportSelf returns the current user's portable data as a downloadable JSON
// document.
func (h *Handler) exportSelf(w http.ResponseWriter, r *http.Request) {
	// A person's data spans every organization they belong to.
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	data, err := h.Service.ExportSelf(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-id-account-export.json"`)
	httpx.WriteJSON(w, http.StatusOK, data)
}

// deleteSelfInput is the body of POST /account/delete.
type deleteSelfInput struct {
	Password string `json:"password"`
}

// deleteSelf erases the current user's PII and credentials at once and ends
// their sessions. The client signs the user out afterwards.
func (h *Handler) deleteSelf(w http.ResponseWriter, r *http.Request) {
	// A person's data spans every organization they belong to.
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	// A stolen access token alone must not delete the account: require the
	// password when the account has one. Password-less (social or passkey)
	// accounts pass on the session alone.
	if h.Reauth != nil {
		var in deleteSelfInput
		_ = httpx.DecodeJSON(r, &in)
		hasPassword, ok, err := h.Reauth.ReauthPassword(r.Context(), *p.UserID, in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if hasPassword && !ok {
			// 400, not 401, so the client does not sign the user out over a mistyped
			// password.
			httpx.WriteError(w, r, errs.ErrBadRequest.WithMessage("Incorrect password."))
			return
		}
	}
	if err := h.Service.PurgeSelf(r.Context(), *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkActOn applies ActOnCheck to the caller of r acting on userID in
// organizationID: nobody erases or exports someone who outranks them.
func (h *Handler) checkActOn(r *http.Request, organizationID, userID uuid.UUID) error {
	if h.ActOnCheck == nil {
		return errs.ErrNotImplemented
	}
	return h.ActOnCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, userID)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.checkActOn(r, tid, in.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	req, err := h.Service.Request(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPROrganizationInvalid)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRIDInvalid)
		return
	}
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Cancel(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createExport(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ExportInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.checkActOn(r, tid, in.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	req, err := h.Service.RequestExport(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) listExports(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPROrganizationInvalid)
		return
	}
	out, err := h.Service.ListExports(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// getExport returns an export request; once it is ready, the response carries
// the payload and a Content-Disposition download header.
func (h *Handler) getExport(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPROrganizationInvalid)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRIDInvalid)
		return
	}
	out, err := h.Service.GetExport(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Reading an export is reading the person's data, held to the same rule as
	// asking for it.
	if err := h.checkActOn(r, tid, out.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if out.Status == "ready" {
		w.Header().Set("Content-Disposition", `attachment; filename="export-`+out.ID.String()+`.json"`)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
