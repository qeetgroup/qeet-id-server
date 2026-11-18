// Package threat records security anomalies in auth.security_events for the
// admin "Threats → Anomalies" screen. Type, severity and status are open
// strings, so a new detection needs no schema change; today's come from the
// sign-in lockout (credential_stuffing and password_spraying).
package threat

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Service records security anomalies and notifies the organization of them.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	notifier notification.Notifier
}

// NewService returns the security anomaly service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// SetNotifier sets the in-app notifier that also alerts the affected user (nil:
// no notifications).
func (s *Service) SetNotifier(n notification.Notifier) { s.notifier = n }

// Event is a detection's input. OrganizationID is required; UserID/IP/UserAgent are
// optional context. Status defaults to "open" and Severity to "low" when empty.
type Event struct {
	OrganizationID uuid.UUID
	UserID         *uuid.UUID
	Type           string
	Severity       string
	Detail         string
	Status         string
	IP             string
	UserAgent      string
	// Metadata is the detection's structured context (e.g. for a lockout the
	// reason, the source network and which counter tripped). Optional.
	Metadata map[string]any
}

// Anomaly is the read projection returned to the admin screen.
type Anomaly struct {
	ID        uuid.UUID  `json:"id"`
	Type      string     `json:"type"`
	Severity  string     `json:"severity"`
	Detail    string     `json:"detail"`
	Status    string     `json:"status"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	UserEmail *string    `json:"user_email,omitempty"`
	IP        *string    `json:"ip,omitempty"`
	// Metadata is the detection's structured context; {} when it has none.
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"created_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
	// ResolvedBy is the person who resolved it, and ResolvedByEmail their
	// email; nil when it is open, or was resolved by no one in particular.
	ResolvedBy      *uuid.UUID `json:"resolved_by,omitempty"`
	ResolvedByEmail *string    `json:"resolved_by_email,omitempty"`
}

// Page is a page of anomalies, newest first, with how many match.
type Page struct {
	paging.Result[Anomaly]
	Total int `json:"total"`
}

// Summary feeds the four KPI cards above the anomaly table.
type Summary struct {
	Open             int `json:"open"`
	Resolved24h      int `json:"resolved_24h"`
	AffectedAccounts int `json:"affected_accounts"`
	HighSeverity24h  int `json:"high_severity_24h"`
}

// Record appends a security event. Detection hooks should log and drop its
// error so a failed write never breaks sign-in.
func (s *Service) Record(ctx context.Context, e Event) error {
	if e.Severity == "" {
		e.Severity = "low"
	}
	if e.Status == "" {
		e.Status = "open"
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	return s.q.InsertSecurityEvent(ctx, dbgen.InsertSecurityEventParams{
		OrganizationID: e.OrganizationID, UserID: e.UserID, Type: e.Type, Severity: e.Severity,
		Detail: e.Detail, Status: e.Status, Ip: e.IP, UserAgent: e.UserAgent, Metadata: meta,
	})
}

// OnAccountLocked implements auth.AnomalyRecorder for each sign-in lock: it
// records a credential_stuffing anomaly for the account's user and organization and
// notifies the user. An account with no organization is skipped; errors are
// logged, not returned.
func (s *Service) OnAccountLocked(ctx context.Context, lock auth.AccountLock) {
	row, err := s.q.GetUserForAnomaly(ctx, lock.Email)
	if err != nil {
		// No matching organization user (unknown email or organization-less) — nothing to
		// scope an organization incident to.
		return
	}
	if row.OrganizationID == nil {
		return
	}
	userID := row.ID
	organizationID := postgres.ZeroIfNull(row.OrganizationID)
	where := "from one network"
	if lock.Counter == auth.CounterAccount {
		where = "from any network"
	}
	if rerr := s.Record(ctx, Event{
		OrganizationID: organizationID,
		UserID:         &userID,
		Type:           "credential_stuffing",
		Severity:       "high",
		Status:         "rate-limited",
		Detail:         "Account temporarily locked after repeated failed sign-in attempts " + where + ".",
		IP:             lock.Network,
		Metadata: map[string]any{
			"reason":         lock.Reason,
			"account":        lock.Email,
			"network":        lock.Network,
			"counter":        lock.Counter,
			"failures":       lock.Failures,
			"threshold":      lock.Threshold,
			"window_minutes": int(lock.Window / time.Minute),
			"locked_until":   lock.LockedUntil,
		},
	}); rerr != nil {
		slog.Warn("record credential_stuffing anomaly", "err", rerr)
	}
	// Also alert the affected user in-app — a "was this you?" security nudge.
	if s.notifier != nil {
		if nerr := s.notifier.Notify(ctx, organizationID, userID, "alert",
			"Unusual sign-in activity",
			"Your account was temporarily locked after several failed sign-in attempts. If this wasn't you, reset your password.",
			"/account/security"); nerr != nil {
			slog.Warn("notify account locked", "err", nerr)
		}
	}
}

// OnSourceThrottled implements auth.AnomalyRecorder for a source network
// throttled for failing against many accounts: it records a password_spraying
// anomaly in each organization whose accounts were targeted. Best effort, like
// OnAccountLocked.
func (s *Service) OnSourceThrottled(ctx context.Context, t auth.SourceThrottle) {
	organizations, err := s.q.ListOrganizationsForEmails(ctx, t.Accounts)
	if err != nil {
		slog.Warn("resolve password_spraying targets", "err", err)
		return
	}
	for _, organizationID := range organizations {
		// Only this organization's own accounts are named on its event.
		targeted, terr := s.q.ListOrganizationUsersForEmails(ctx, dbgen.ListOrganizationUsersForEmailsParams{OrganizationID: organizationID, Emails: t.Accounts})
		if terr != nil {
			slog.Warn("resolve password_spraying accounts", "err", terr)
			continue
		}
		if rerr := s.Record(ctx, Event{
			OrganizationID: organizationID,
			Type:           "password_spraying",
			Severity:       "high",
			Status:         "rate-limited",
			Detail:         "A network was blocked from password sign-in after failing against many accounts, including accounts in this organization.",
			IP:             t.Network,
			Metadata: map[string]any{
				"reason":            t.Reason,
				"network":           t.Network,
				"counter":           auth.CounterSource,
				"distinct_accounts": len(t.Accounts),
				"window_minutes":    int(t.Window / time.Minute),
				"throttled_until":   t.ThrottledUntil,
				"targeted_accounts": len(targeted),
				"targeted_user_ids": targeted,
			},
		}); rerr != nil {
			slog.Warn("record password_spraying anomaly", "err", rerr)
		}
	}
}

// List returns a page of up to limit of the organization's anomalies (50 when
// unset, at most 200), newest first, after the cursor, of status when given,
// and how many match.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, limit int, after paging.Cursor, status string) (*Page, error) {
	limit = paging.Clamp(limit, 50, 200)
	total, err := s.q.CountSecurityEvents(ctx, dbgen.CountSecurityEventsParams{OrganizationID: organizationID, Status: status})
	if err != nil {
		return nil, err
	}
	params := dbgen.ListSecurityEventsParams{OrganizationID: organizationID, Status: status, Lim: int32(limit + 1)} // #nosec G115 -- at most 201
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListSecurityEvents(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]Anomaly, 0, len(rows))
	for _, row := range rows {
		a := Anomaly{
			ID: row.ID, Type: row.Type, Severity: row.Severity, Detail: row.Detail, Status: row.Status,
			UserID: row.UserID, UserEmail: row.UserEmail, IP: postgres.NullIfZero(row.Ip), CreatedAt: row.CreatedAt,
			ResolvedAt: row.ResolvedAt, ResolvedBy: row.ResolvedBy, ResolvedByEmail: row.ResolvedByEmail,
		}
		if err := json.Unmarshal(row.Metadata, &a.Metadata); err != nil {
			return nil, err
		}
		items = append(items, a)
	}
	return &Page{
		Result: paging.Page(paging.Next(items, limit, func(a Anomaly) (time.Time, uuid.UUID) { return a.CreatedAt, a.ID })),
		Total:  int(total),
	}, nil
}

// Summary computes the KPI counts for an organization in a single pass.
func (s *Service) Summary(ctx context.Context, organizationID uuid.UUID) (*Summary, error) {
	row, err := s.q.GetSecurityEventSummary(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	return &Summary{
		Open:             int(row.Open),
		Resolved24h:      int(row.Resolved24h),
		AffectedAccounts: int(row.AffectedAccounts),
		HighSeverity24h:  int(row.HighSeverity24h),
	}, nil
}

// Resolve marks an open anomaly resolved, recorded as actor's. Organization-scoped so
// an admin can never resolve another organization's incident.
func (s *Service) Resolve(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	resolvedBy := actor.UserID
	row, err := s.q.WithTx(tx).ResolveSecurityEvent(ctx, dbgen.ResolveSecurityEventParams{
		ID:             id,
		OrganizationID: organizationID,
		ResolvedBy:     resolvedBy,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	metadata := map[string]any{"type": row.Type, "severity": row.Severity}
	if row.UserID != nil {
		metadata["user_id"] = *row.UserID
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "anomaly.resolved", "security_event", id, metadata)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
