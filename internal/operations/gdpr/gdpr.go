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

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Request is a right-to-erasure request.
type Request struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	RequestedBy *uuid.UUID `json:"requested_by"`
	Reason      *string    `json:"reason"`
	Status      string     `json:"status"`
	GraceUntil  time.Time  `json:"grace_until"`
	CompletedAt *time.Time `json:"completed_at"`
	CreatedAt   time.Time  `json:"created_at"`
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
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	Reason   string     `json:"reason"`
	By       *uuid.UUID `json:"-"`
}

// Request files an erasure request for a user whose home tenant is
// in.TenantID; other users return errs.ErrNotFound. The purge runs once the
// grace period ends.
func (s *Service) Request(ctx context.Context, in CreateInput) (*Request, error) {
	owned, err := s.userBelongsToTenant(ctx, in.UserID, in.TenantID)
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
	row, err := s.q.InsertPurgeRequest(ctx, dbgen.InsertPurgeRequestParams{
		TenantID:    in.TenantID,
		UserID:      in.UserID,
		RequestedBy: pgUUIDNullable(in.By),
		Reason:      reason,
		GraceUntil:  time.Now().UTC().Add(s.grace),
	})
	if err != nil {
		return nil, err
	}
	return purgeRequestFromRow(dbgen.ListPurgeRequestsRow(row)), nil
}

// userBelongsToTenant reports whether tenantID is the user's home tenant
// (users.tenant_id), not merely one where the user holds a role. Erasure is
// irreversible, so only the owning tenant may order it.
func (s *Service) userBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var owned bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM "user".users
			WHERE id = $1 AND tenant_id = $2
		)
	`, userID, tenantID).Scan(&owned)
	return owned, err
}

// Cancel cancels one of the tenant's pending erasure requests. It returns
// errs.ErrNotFound if there is no such pending request.
func (s *Service) Cancel(ctx context.Context, tenantID, id uuid.UUID) error {
	ct, err := s.q.CancelPurgeRequest(ctx, dbgen.CancelPurgeRequestParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if ct == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// List returns the tenant's 200 most recent erasure requests, newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Request, error) {
	rows, err := s.q.ListPurgeRequests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		out = append(out, *purgeRequestFromRow(r))
	}
	return out, nil
}

// purgeRequestFromRow converts a purge-request row to a Request.
func purgeRequestFromRow(r dbgen.ListPurgeRequestsRow) *Request {
	return &Request{
		ID:          r.ID,
		TenantID:    r.TenantID,
		UserID:      r.UserID,
		RequestedBy: toUUIDPtr(r.RequestedBy),
		Reason:      r.Reason,
		Status:      r.Status,
		GraceUntil:  r.GraceUntil,
		CompletedAt: toTimePtr(r.CompletedAt),
		CreatedAt:   r.CreatedAt,
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
			FROM "user".purge_requests
			WHERE status = 'pending' AND grace_until <= NOW()
			  AND (lease_until IS NULL OR lease_until <= NOW())
			ORDER BY grace_until, created_at
			LIMIT 50
			FOR UPDATE SKIP LOCKED
		)
		UPDATE "user".purge_requests AS request
		SET lease_owner = $1, lease_until = $2
		FROM candidates
		WHERE request.id = candidates.id
		RETURNING request.id, request.user_id
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
			slog.Warn("gdpr purge", "user", e.UserID, "err", err)
		}
	}
	return nil
}

// purgeOne erases the user of one leased request. If the user's home tenant
// does not match the request's, the request is quarantined instead.
func (s *Service) purgeOne(ctx context.Context, requestID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	qTx := dbgen.New(tx)
	var requestTenant uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT tenant_id
		FROM "user".purge_requests
		WHERE id = $1 AND user_id = $2 AND status = 'pending' AND lease_owner = $3
		FOR UPDATE
	`, requestID, userID, s.workerID).Scan(&requestTenant); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}

	var userTenant *uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT tenant_id FROM "user".users WHERE id = $1 FOR UPDATE
	`, userID).Scan(&userTenant); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if userTenant == nil || *userTenant != requestTenant {
		if _, err := tx.Exec(ctx, `
			UPDATE "user".purge_requests
			SET status = 'quarantined', quarantined_at = NOW(),
			    quarantine_reason = 'tenant ownership mismatch detected by worker',
			    lease_owner = NULL, lease_until = NULL
			WHERE id = $1 AND status = 'pending' AND lease_owner = $2
		`, requestID, s.workerID); err != nil {
			return err
		}
		slog.Warn("gdpr purge quarantined", "request_id", requestID, "user_id", userID, "tenant_id", requestTenant)
		return tx.Commit(ctx)
	}

	if err := s.purgeTenantUserData(ctx, tx, qTx, requestTenant, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE "user".purge_requests
		SET status = 'completed', completed_at = NOW(), lease_owner = NULL, lease_until = NULL
		WHERE id = $1 AND status = 'pending' AND lease_owner = $2
	`, requestID, s.workerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("GDPR purge lease lost before completion")
	}
	return tx.Commit(ctx)
}

func (s *Service) purgeTenantUserData(ctx context.Context, tx pgx.Tx, qTx *dbgen.Queries, tenantID, userID uuid.UUID) error {
	// Sessions first, announced before anything about the account is redacted.
	if err := s.endSessions(ctx, tx, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE "user".users
		SET email              = 'redacted-' || id::text || '@gdpr.invalid',
		    phone              = NULL,
		    display_name       = NULL,
		    metadata           = '{}'::jsonb,
		    email_verified_at  = NULL,
		    phone_verified_at  = NULL,
		    status             = 'deleted',
		    deleted_at         = COALESCE(deleted_at, NOW()),
		    updated_at         = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errs.ErrNotFound
	}
	if err := qTx.DeletePasswordCredentials(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	return nil
}

// purgeUserData ends the user's sessions, redacts their PII and deletes their
// password, TOTP and recovery codes. The redacted user row and the audit rows
// are kept, so past events stay verifiable.
func (s *Service) purgeUserData(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Sessions first, announced before anything about the account is redacted.
	if err := s.endSessions(ctx, tx, userID); err != nil {
		return err
	}
	qTx := dbgen.New(tx)
	if err := qTx.PurgeUserPII(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeletePasswordCredentials(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	return nil
}

// PurgeSelf erases the current user's PII and credentials at once, with no grace
// period, for self-service account deletion. Audit references are kept.
func (s *Service) PurgeSelf(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.purgeUserData(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ExportRequest is a data-export job. The background sweep (exportSweepTick)
// fills in Payload and sets Status to "ready".
type ExportRequest struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	UserID      uuid.UUID      `json:"user_id"`
	RequestedBy *uuid.UUID     `json:"requested_by"`
	Status      string         `json:"status"`
	Payload     map[string]any `json:"payload,omitempty"`
	Error       *string        `json:"error,omitempty"`
	CompletedAt *time.Time     `json:"completed_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

// ExportInput is a data-export request to queue.
type ExportInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	By       *uuid.UUID `json:"-"`
}

// RequestExport queues a data export for a user whose home tenant is
// in.TenantID. The background sweep builds it; poll GetExport for the result.
func (s *Service) RequestExport(ctx context.Context, in ExportInput) (*ExportRequest, error) {
	owned, err := s.userBelongsToTenant(ctx, in.UserID, in.TenantID)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, errs.ErrNotFound
	}
	row, err := s.q.InsertExportRequest(ctx, dbgen.InsertExportRequestParams{
		TenantID:    in.TenantID,
		UserID:      in.UserID,
		RequestedBy: pgUUIDNullable(in.By),
	})
	if err != nil {
		return nil, err
	}
	return &ExportRequest{
		ID:          row.ID,
		TenantID:    row.TenantID,
		UserID:      row.UserID,
		RequestedBy: toUUIDPtr(row.RequestedBy),
		Status:      row.Status,
		CompletedAt: toTimePtr(row.CompletedAt),
		CreatedAt:   row.CreatedAt,
	}, nil
}

// ListExports returns the tenant's 200 most recent export requests, newest
// first, without payloads.
func (s *Service) ListExports(ctx context.Context, tenantID uuid.UUID) ([]ExportRequest, error) {
	rows, err := s.q.ListExportRequests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ExportRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExportRequest{
			ID:          r.ID,
			TenantID:    r.TenantID,
			UserID:      r.UserID,
			RequestedBy: toUUIDPtr(r.RequestedBy),
			Status:      r.Status,
			Error:       r.Error,
			CompletedAt: toTimePtr(r.CompletedAt),
			CreatedAt:   r.CreatedAt,
		})
	}
	return out, nil
}

// GetExport returns one of the tenant's export requests, with its payload once
// ready.
func (s *Service) GetExport(ctx context.Context, tenantID, id uuid.UUID) (*ExportRequest, error) {
	r, err := s.q.GetExportRequest(ctx, dbgen.GetExportRequestParams{
		ID:       id,
		TenantID: tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &ExportRequest{
		ID:          r.ID,
		TenantID:    r.TenantID,
		UserID:      r.UserID,
		RequestedBy: toUUIDPtr(r.RequestedBy),
		Status:      r.Status,
		Error:       r.Error,
		CompletedAt: toTimePtr(r.CompletedAt),
		CreatedAt:   r.CreatedAt,
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
			FROM "user".export_requests
			WHERE status = 'pending' AND (lease_until IS NULL OR lease_until <= NOW())
			ORDER BY created_at
			LIMIT 20
			FOR UPDATE SKIP LOCKED
		)
		UPDATE "user".export_requests AS request
		SET lease_owner = $1, lease_until = $2
		FROM candidates
		WHERE request.id = candidates.id
		RETURNING request.id, request.tenant_id, request.user_id
	`, s.workerID, time.Now().UTC().Add(s.lease))
	if err != nil {
		return err
	}
	type exportJob struct{ ID, TenantID, UserID uuid.UUID }
	var batch []exportJob
	for rows.Next() {
		var job exportJob
		if err := rows.Scan(&job.ID, &job.TenantID, &job.UserID); err != nil {
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
		if err := s.buildExport(ctx, e.ID, e.TenantID, e.UserID); err != nil {
			slog.Warn("gdpr export", "user", e.UserID, "err", err)
			msg := err.Error()
			_, _ = s.pool.Exec(ctx, `
				UPDATE "user".export_requests
				SET status = 'failed', error = $3, completed_at = NOW(),
				    lease_owner = NULL, lease_until = NULL
				WHERE id = $1 AND lease_owner = $2
			`, e.ID, s.workerID, msg)
		}
	}
	return nil
}

func (s *Service) buildExport(ctx context.Context, requestID, tenantID, userID uuid.UUID) error {
	payload, err := s.collectUserData(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE "user".export_requests
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
	return nil
}

type exportProfile struct {
	Email           string     `json:"email"`
	Phone           *string    `json:"phone,omitempty"`
	DisplayName     *string    `json:"display_name,omitempty"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt *time.Time `json:"phone_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
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

// collectUserData assembles one user's portable data in a tenant: profile,
// sessions, passkeys, MFA status and roles. Credentials (password hashes, TOTP
// secrets, recovery codes) are excluded.
func (s *Service) collectUserData(ctx context.Context, tenantID, userID uuid.UUID) (map[string]any, error) {
	// user.users.tenant_id is nullable, so it takes a pgtype.UUID.
	profileRow, err := s.q.GetUserProfileForExport(ctx, dbgen.GetUserProfileForExportParams{
		UserID:   userID,
		TenantID: pgUUIDNullable(&tenantID),
	})
	if err != nil {
		return nil, err
	}
	profile := exportProfile{
		Email:           profileRow.Email,
		Phone:           profileRow.Phone,
		DisplayName:     profileRow.DisplayName,
		Status:          profileRow.Status,
		EmailVerifiedAt: toTimePtr(profileRow.EmailVerifiedAt),
		PhoneVerifiedAt: toTimePtr(profileRow.PhoneVerifiedAt),
		CreatedAt:       profileRow.CreatedAt,
	}

	// auth.sessions.tenant_id is nullable, so it takes a pgtype.UUID.
	sessRows, err := s.q.ListUserSessionsForExport(ctx, dbgen.ListUserSessionsForExportParams{
		UserID:   userID,
		TenantID: pgUUIDNullable(&tenantID),
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
		UserID:   userID,
		TenantID: tenantID,
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

	return map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}, nil
}

type exportSelfRole struct {
	RoleName     string    `json:"role_name"`
	Organization string    `json:"organization"`
	GrantedAt    time.Time `json:"granted_at"`
}

// ExportSelf assembles the current user's portable data across all their
// organizations, with no tenant scope: a self-service user may have no tenant.
// Credentials are excluded.
func (s *Service) ExportSelf(ctx context.Context, userID uuid.UUID) (map[string]any, error) {
	var profile exportProfile
	if err := s.pool.QueryRow(ctx, `
		SELECT email, phone, display_name, status, email_verified_at, phone_verified_at, created_at
		FROM "user".users
		WHERE id = $1`, userID,
	).Scan(&profile.Email, &profile.Phone, &profile.DisplayName, &profile.Status,
		&profile.EmailVerifiedAt, &profile.PhoneVerifiedAt, &profile.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}

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
		JOIN tenant.tenants t ON t.id = ur.tenant_id
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

	return map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}, nil
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
}

// Mount registers the routes.
func (h *Handler) Mount(r chi.Router) {
	// Self-service: the signed-in user acts on their own account, and no tenant
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

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tid
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		in.By = p.UserID
	}
	req, err := h.Service.Request(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRTenantInvalid)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRIDInvalid)
		return
	}
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Cancel(r.Context(), tid, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createExport(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ExportInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tid
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		in.By = p.UserID
	}
	req, err := h.Service.RequestExport(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) listExports(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRTenantInvalid)
		return
	}
	out, err := h.Service.ListExports(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// getExport returns an export request; once it is ready, the response carries
// the payload and a Content-Disposition download header.
func (h *Handler) getExport(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRTenantInvalid)
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
	if out.Status == "ready" {
		w.Header().Set("Content-Disposition", `attachment; filename="export-`+out.ID.String()+`.json"`)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
