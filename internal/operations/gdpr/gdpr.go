// Package gdpr handles right-to-erasure requests. A request enters with
// a grace period; a background job purges PII once the grace expires.
// PII is replaced with a redacted marker so audit references remain intact.
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

type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	grace    time.Duration
	workerID uuid.UUID
	lease    time.Duration
	// signals announces the sessions an erasure ends (nil = announces
	// nothing). Set via SetSessionSignals.
	signals *sessionsignal.Signaller
}

// SetSessionSignals wires the announcement of ended sessions. Called from
// internal/bootstrap/dependencies.go.
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

func NewService(pool *pgxpool.Pool, grace time.Duration) *Service {
	if grace <= 0 {
		grace = 30 * 24 * time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), grace: grace, workerID: uuid.New(), lease: 15 * time.Minute}
}

type CreateInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	Reason   string     `json:"reason"`
	By       *uuid.UUID `json:"-"`
}

func (s *Service) Request(ctx context.Context, in CreateInput) (*Request, error) {
	owned, err := s.userBelongsToTenant(ctx, in.UserID, in.TenantID)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, errs.ErrNotFound
	}
	// grace_until is pre-computed here (instead of NOW() + $5::interval) to
	// avoid the pgtype.Interval parameter type mismatch in sqlc-generated code.
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
	return purgeRequestFromRow(row), nil
}

// userBelongsToTenant keys off users.tenant_id — the user's home tenant —
// rather than rbac.user_roles membership, which is what OIDC authorization
// uses. The two answers differ for a guest who holds a role in another tenant,
// and that difference is deliberate: erasure is destructive and irreversible,
// so only the tenant that owns the record may order it. A tenant the user
// merely has a role in can revoke that role, not delete the person.
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

// purgeRequestFromRow maps a generated UserPurgeRequest model to the domain
// Request type.
func purgeRequestFromRow(r dbgen.UserPurgeRequest) *Request {
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

// Run is the background sweeper. It picks ripe purge requests and erases
// PII from the user row + drops auth credentials. Audit rows are kept.
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

// Sweep runs a single purge pass over ripe requests — the same work Run does on
// each tick. Exposed for ops-triggered purges and tests.
func (s *Service) Sweep(ctx context.Context) error { return s.tick(ctx) }

// SweepExports claims and processes one export batch.
func (s *Service) SweepExports(ctx context.Context) error { return s.exportSweepTick(ctx) }

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

// purgeUserData replaces the user's PII with redacted markers and drops all
// sign-in credentials (password, TOTP, recovery codes) + revokes sessions. The
// user row is kept as a redacted tombstone and audit rows are left intact, so
// historical events stay verifiable. Shared by the admin grace-period sweep and
// self-service deletion.
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

// PurgeSelf immediately erases the current user's own PII and credentials — no
// grace period. Backs the self-service "delete my account" action; audit
// references are preserved (redacted), matching the admin erasure guarantees.
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

// ExportRequest is a queued/completed GDPR data-export job. Payload is filled
// in by the background sweep (exportTick) once status flips to "ready".
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

type ExportInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	By       *uuid.UUID `json:"-"`
}

// RequestExport queues a data-export job for a user. The background sweep
// (exportTick) builds the payload asynchronously; poll GetExport for status.
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

// ListExports returns a tenant's export requests, most recent first.
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

// GetExport fetches one export request, including its payload once ready.
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

// exportSweepTick picks pending export requests and builds their payload.
// Runs on the same ticker cadence as the purge sweep (see Run).
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

// collectUserData assembles the GDPR-portable data for one user: profile,
// sessions, passkey/MFA metadata (no secrets or credential material), and
// role assignments. Password hashes, TOTP secrets, and recovery-code hashes
// are deliberately excluded — they're credentials, not personal data.
func (s *Service) collectUserData(ctx context.Context, tenantID, userID uuid.UUID) (map[string]any, error) {
	// user.users.tenant_id is nullable → pgtype.UUID param.
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

	// auth.sessions.tenant_id is nullable (migration 0026) → pgtype.UUID param.
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

	// GetUserMFAStatus returns ErrNoRows when the user has no TOTP row — that
	// means mfaEnabled is false (the zero value), which is correct.
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

// ExportSelf assembles the GDPR-portable data for the *current* user, across all
// their organizations and independent of any tenant scope (a self-service user
// may be tenant-less, so this can't reuse the tenant-filtered admin queries).
// Credential material — password hashes, TOTP secrets, recovery-code hashes — is
// deliberately excluded. Returned synchronously so the caller can download it.
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

	// ErrNoRows means no TOTP row → not enrolled (false zero value is correct).
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

// ReauthChecker re-verifies a caller's password before an irreversible action.
// Injected from the auth service; nil disables the gate.
type ReauthChecker interface {
	ReauthPassword(ctx context.Context, userID uuid.UUID, plain string) (hasPassword, ok bool, err error)
}

type Handler struct {
	Service  *Service
	Evidence *EvidenceService
	// Reauth gates account deletion behind a password re-prove (when the account
	// has a password). Nil = gate off.
	Reauth ReauthChecker
}

func (h *Handler) Mount(r chi.Router) {
	// Self-service (the current user acts on their own account, no tenant
	// required) — mirrors /v1/me; not in the RBAC permission map, so any authed
	// user passes through.
	r.Post("/account/export", h.exportSelf)
	r.Post("/account/delete", h.deleteSelf)

	r.Post("/gdpr/purge", h.create)
	r.Get("/tenants/{tenantID}/gdpr/purge", h.list)
	r.Delete("/gdpr/purge/{id}", h.cancel)

	r.Post("/gdpr/export", h.createExport)
	r.Get("/tenants/{tenantID}/gdpr/export", h.listExports)
	r.Get("/tenants/{tenantID}/gdpr/export/{id}", h.getExport)

	// Compliance evidence routes — SOC 2 and ISO 27001 live checks.
	h.mountEvidence(r)
}

// exportSelf returns the current user's own portable data as a downloadable
// JSON document (synchronous — the payload is small). Self-service, no tenant.
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

// deleteSelf immediately erases the current user's PII + credentials and revokes
// their sessions (self-service "delete my account"). No grace period; audit
// references are kept redacted. The caller is signed out client-side afterwards.
type deleteSelfInput struct {
	Password string `json:"password"`
}

func (h *Handler) deleteSelf(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	// Re-prove identity before this irreversible purge: a stolen access token
	// alone must not be enough. When the account has a password we require it;
	// password-less (social/passkey) accounts are already strongly authenticated,
	// so they pass on the session alone.
	if h.Reauth != nil {
		var in deleteSelfInput
		_ = httpx.DecodeJSON(r, &in)
		hasPassword, ok, err := h.Reauth.ReauthPassword(r.Context(), *p.UserID, in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if hasPassword && !ok {
			// 400 (not 401) so the client's session-expiry handling doesn't log the
			// user out on a mistyped confirmation password.
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

// getExport returns the export request; once status is "ready" the response
// includes the full payload with a Content-Disposition download header.
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
