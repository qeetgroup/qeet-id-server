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
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/threat/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Notifier sends an in-app notification to a user. Satisfied by
// *notification.Service; an interface so threat doesn't import that package.
type Notifier interface {
	Notify(ctx context.Context, organizationID, userID uuid.UUID, kind, title, description, href string) error
}

// Service records security anomalies and notifies the organization of them.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	notifier Notifier
}

// NewService returns the security anomaly service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// SetNotifier sets the in-app notifier that also alerts the affected user (nil:
// no notifications).
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

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
	Items      []Anomaly `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	Total      int       `json:"total"`
}

// Summary feeds the four KPI cards above the anomaly table.
type Summary struct {
	Open             int `json:"open"`
	Resolved24h      int `json:"resolved_24h"`
	AffectedAccounts int `json:"affected_accounts"`
	HighSeverity24h  int `json:"high_severity_24h"`
}

// Record appends a security event. Detection hooks should log and drop its
// error so a failed write never breaks sign-in. The INSERT is hand-written
// because sqlc can't infer the parameter type of its NULLIF(...)::inet cast.
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
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth.security_events (organization_id, user_id, type, severity, detail, status, ip, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,'')::inet, NULLIF($8,''), $9)
	`, e.OrganizationID, e.UserID, e.Type, e.Severity, e.Detail, e.Status, e.IP, e.UserAgent, meta)
	return err
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
	if !row.OrganizationID.Valid {
		return
	}
	userID := row.ID
	organizationID := uuid.UUID(row.OrganizationID.Bytes)
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
			Detail:         "A network was blocked from password sign-in after failing against many accounts, including accounts in this organisation.",
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

// List returns a page of up to limit of the organization's anomalies (50 when not
// in 1..200), newest first, after cursor, of status when given, and how many
// match.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, limit int, cursor, status string) (*Page, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	page := &Page{Items: []Anomaly{}}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM auth.security_events WHERE organization_id = $1 AND ($2 = '' OR status = $2)`,
		organizationID, status).Scan(&page.Total); err != nil {
		return nil, err
	}
	afterTs, afterID := time.Now().Add(time.Hour), uuid.Max
	if cursor != "" {
		var err error
		if afterTs, afterID, err = paging.DecodeTimeUUID(cursor); err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.type, e.severity, e.detail, e.status, e.user_id, u.email,
		       host(e.ip), e.metadata, e.created_at, e.resolved_at, e.resolved_by, rb.email
		FROM auth.security_events e
		LEFT JOIN account.users u ON u.id = e.user_id
		LEFT JOIN account.users rb ON rb.id = e.resolved_by
		WHERE e.organization_id = $1 AND ($2 = '' OR e.status = $2) AND (e.created_at, e.id) < ($3, $4)
		ORDER BY e.created_at DESC, e.id DESC
		LIMIT $5
	`, organizationID, status, afterTs, afterID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.Detail, &a.Status,
			&a.UserID, &a.UserEmail, &a.IP, &a.Metadata, &a.CreatedAt, &a.ResolvedAt, &a.ResolvedBy, &a.ResolvedByEmail); err != nil {
			return nil, err
		}
		page.Items = append(page.Items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = paging.EncodeTimeUUID(last.CreatedAt, last.ID)
	}
	return page, nil
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
	var resolvedBy pgtype.UUID
	if actor.UserID != nil {
		resolvedBy = pgtype.UUID{Bytes: *actor.UserID, Valid: true}
	}
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
	if row.UserID.Valid {
		metadata["user_id"] = uuid.UUID(row.UserID.Bytes)
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "anomaly.resolved", "security_event", id, metadata)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Handler serves the security anomaly HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the security anomaly routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/security/anomalies", h.list)
	r.Get("/tenants/{tenantID}/security/anomalies/summary", h.summary)
	r.Post("/tenants/{tenantID}/security/anomalies/{id}/resolve", h.resolve)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	status := query.Get("status")
	if status != "" && status != "open" && status != "resolved" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid status"))
		return
	}
	page, err := h.Service.List(r.Context(), organizationID, limit, query.Get("cursor"), status)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sm, err := h.Service.Summary(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sm)
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Resolve(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Anomaly resolved."})
}
