package directory

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Event is one recorded provisioning operation.
type Event struct {
	ID           uuid.UUID  `json:"id"`
	ConnectionID string     `json:"connection_id"`
	Operation    string     `json:"operation"`
	Trigger      string     `json:"trigger"`
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	StartedAt    time.Time  `json:"started_at"`
	DurationMS   int64      `json:"duration_ms"`
	HTTPStatus   int        `json:"http_status"`
	Status       string     `json:"status"`
	UsersSynced  int        `json:"users_synced"`
	GroupsSynced int        `json:"groups_synced"`
	ErrorCode    string     `json:"error_code"`
	Message      string     `json:"message"`
	Category     string     `json:"category"`
	Severity     string     `json:"severity"`
	Resolution   string     `json:"resolution"`
	ResolvedAt   *time.Time `json:"resolved_at"`
	RetryOf      *uuid.UUID `json:"retry_of"`
	Retryable    bool       `json:"retryable"`
}

// EventSummary counts the events on a page's filter by outcome.
type EventSummary struct {
	Total             int    `json:"total"`
	Successful        int    `json:"successful"`
	Warnings          int    `json:"warnings"`
	Failed            int    `json:"failed"`
	AverageDurationMS *int64 `json:"average_duration_ms"`
}

// VolumePoint is a day's count of user and group operations.
type VolumePoint struct {
	Date   string `json:"date"`
	Users  int    `json:"users"`
	Groups int    `json:"groups"`
}

// EventPage is one page of events with their summary.
type EventPage struct {
	Items   []Event       `json:"items"`
	Total   int           `json:"total"`
	Summary EventSummary  `json:"summary"`
	Volume  []VolumePoint `json:"volume"`
	Offset  int           `json:"offset"`
	Limit   int           `json:"limit"`
}

type eventFilter struct {
	Since        time.Time
	ConnectionID string
	Status       string
	Search       string
	Limit        int
	Offset       int
}

// SetEventStore sets the pool that events are recorded to and read from.
func (service *Service) SetEventStore(pool *pgxpool.Pool) {
	service.pool = pool
}

func classifyOperation(operation string, status int) (outcome, category, code, message, severity string) {
	if status >= 200 && status < 300 {
		return "success", "", "", "Operation completed", ""
	}
	// A person's own credentials refused at sign-in is a sign-in's outcome, not
	// a fault of the connection: a warning, never an open error or an alert.
	if operation == "sign-in" && status == http.StatusUnauthorized {
		return "warning", "credentials", "DIR-401", "The person's directory credentials were refused", ""
	}
	outcome, category, severity = "failed", "provisioning", "warning"
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		category, message, severity = "permission", "Directory access was denied", "critical"
	case status == http.StatusConflict:
		category, message = "provisioning", "An identity or group already exists"
	case status == http.StatusNotFound:
		message = "The requested directory object was not found"
	case status == http.StatusTooManyRequests:
		category, message = "limit", "The directory request limit was reached"
	case status >= 500:
		category, message, severity = "connection", "The directory operation could not be completed", "critical"
	default:
		category, message = "validation", "The directory request could not be validated"
	}
	return outcome, category, "DIR-" + strconv.Itoa(status), message, severity
}

// RecordOperation records one provisioning operation of a connection.
func (service *Service) RecordOperation(ctx context.Context, tenantID uuid.UUID, connectionID, operation, resourceType, resourceID string, status int, started time.Time, duration time.Duration) error {
	if service.pool == nil {
		return nil
	}
	if tenantID == uuid.Nil || !validConnectionID(tenantID, connectionID) || status < 100 || status > 599 {
		return errs.ErrBadRequest
	}
	if resourceType != "user" && resourceType != "group" && resourceType != "connection" {
		return errs.ErrBadRequest
	}
	if len(resourceID) > 128 {
		resourceID = ""
	}
	outcome, category, code, message, severity := classifyOperation(operation, status)
	trigger := "manual"
	if strings.HasPrefix(connectionID, "scim:") {
		trigger = "push"
	} else if operation == "sign-in" {
		trigger = "sign-in"
	}
	users, groups := 0, 0
	if outcome == "success" && resourceType == "user" {
		users = 1
	}
	if outcome == "success" && resourceType == "group" {
		groups = 1
	}
	_, err := service.pool.Exec(ctx, `
		INSERT INTO tenant.directory_events
		(id,tenant_id,connection_id,operation,trigger_type,resource_type,resource_id,started_at,duration_ms,http_status,status,users_synced,groups_synced,error_code,message,category,severity,retry_of)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		uuid.New(), tenantID, connectionID, operation, trigger, resourceType, resourceID, started.UTC(), max(0, duration.Milliseconds()), status, outcome, users, groups, code, message, category, severity, ctx.Value(retryContextKey{}))
	if err != nil {
		return err
	}
	if outcome == "failed" {
		return service.notifyAlerts(ctx, tenantID, connectionID)
	}
	if outcome == "success" {
		return service.resolveConnectionFailures(ctx, tenantID, connectionID)
	}
	return nil
}

// resolveConnectionFailures marks the connection's open failures of the kind a
// success disproves, the directory unreachable or refusing the connection's
// own credentials, resolved by the system, and audits it once. A failure being
// retried is left for its retry to settle.
func (service *Service) resolveConnectionFailures(ctx context.Context, tenantID uuid.UUID, connectionID string) error {
	retrying, _ := ctx.Value(retryContextKey{}).(uuid.UUID)
	const open = `tenant_id=$1 AND connection_id=$2 AND status='failed' AND resolution='open'
		  AND category IN ('connection','permission') AND id <> $3`
	// Most successes find nothing to resolve; only then is a transaction opened.
	var found bool
	if err := service.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant.directory_events WHERE `+open+`)`,
		tenantID, connectionID, retrying).Scan(&found); err != nil || !found {
		return err
	}
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `UPDATE tenant.directory_events SET resolution='resolved', resolved_at=NOW(), resolved_by=NULL
		WHERE `+open+` RETURNING id`, tenantID, connectionID, retrying)
	if err != nil {
		return err
	}
	var resolved []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		resolved = append(resolved, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(resolved) == 0 {
		return nil
	}
	if err := audit.Record(ctx, tx, audit.Event{TenantID: &tenantID, ActorType: "system", Action: "directory.errors_resolved",
		ResourceType: "directory_connection", Metadata: map[string]any{"connection_id": connectionID, "events": resolved, "reason": "a later operation succeeded"}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validConnectionID(tenantID uuid.UUID, connectionID string) bool {
	if connectionID == "scim:"+tenantID.String() {
		return true
	}
	parsed, err := uuid.Parse(connectionID)
	return err == nil && parsed != uuid.Nil
}

func parseEventFilter(request *http.Request) (eventFilter, error) {
	filter := eventFilter{Since: time.Now().UTC().AddDate(0, 0, -7), Limit: 25}
	query := request.URL.Query()
	if value := query.Get("days"); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil || days < 1 || days > 90 {
			return filter, errs.ErrBadRequest
		}
		filter.Since = time.Now().UTC().AddDate(0, 0, -days)
	}
	for key, destination := range map[string]*int{"limit": &filter.Limit, "offset": &filter.Offset} {
		if value := query.Get(key); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || (key == "limit" && (parsed < 1 || parsed > 100)) || parsed > 100000 {
				return filter, errs.ErrBadRequest
			}
			*destination = parsed
		}
	}
	filter.ConnectionID = query.Get("connection_id")
	filter.Status = query.Get("status")
	filter.Search = strings.TrimSpace(query.Get("q"))
	if len(filter.ConnectionID) > 128 || len(filter.Search) > 200 {
		return filter, errs.ErrBadRequest
	}
	if filter.Status != "" && filter.Status != "success" && filter.Status != "warning" && filter.Status != "failed" {
		return filter, errs.ErrBadRequest
	}
	return filter, nil
}

const eventColumns = `id,connection_id,operation,trigger_type,resource_type,resource_id,started_at,duration_ms,http_status,status,users_synced,groups_synced,error_code,message,category,severity,resolution,resolved_at,retry_of`
const eventWhere = `tenant_id=$1 AND started_at >= $2 AND ($3='' OR connection_id=$3) AND ($4='' OR status=$4) AND ($5='' OR operation ILIKE '%'||$5||'%' OR message ILIKE '%'||$5||'%' OR error_code ILIKE '%'||$5||'%')`

func scanEvent(row pgx.Row) (Event, error) {
	var event Event
	err := row.Scan(&event.ID, &event.ConnectionID, &event.Operation, &event.Trigger, &event.ResourceType, &event.ResourceID, &event.StartedAt, &event.DurationMS, &event.HTTPStatus, &event.Status, &event.UsersSynced, &event.GroupsSynced, &event.ErrorCode, &event.Message, &event.Category, &event.Severity, &event.Resolution, &event.ResolvedAt, &event.RetryOf)
	event.Retryable = event.Status != "success" && event.Resolution == "open" && event.Operation == "test" && !strings.HasPrefix(event.ConnectionID, "scim:")
	return event, err
}

// Events returns one page of the tenant's provisioning events.
func (service *Service) Events(ctx context.Context, tenantID uuid.UUID, filter eventFilter) (EventPage, error) {
	page := EventPage{Items: []Event{}, Volume: []VolumePoint{}, Limit: filter.Limit, Offset: filter.Offset}
	if tenantID == uuid.Nil || service.pool == nil {
		return page, errs.ErrUnauthorized
	}
	arguments := []any{tenantID, filter.Since, filter.ConnectionID, filter.Status, filter.Search}
	err := service.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE status='success'),count(*) FILTER(WHERE status='warning'),count(*) FILTER(WHERE status='failed'),round(avg(duration_ms))::bigint FROM tenant.directory_events WHERE `+eventWhere, arguments...).Scan(&page.Summary.Total, &page.Summary.Successful, &page.Summary.Warnings, &page.Summary.Failed, &page.Summary.AverageDurationMS)
	if err != nil {
		return page, err
	}
	page.Total = page.Summary.Total
	rows, err := service.pool.Query(ctx, `SELECT `+eventColumns+` FROM tenant.directory_events WHERE `+eventWhere+` ORDER BY started_at DESC,id DESC LIMIT $6 OFFSET $7`, append(arguments, filter.Limit, filter.Offset)...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			return page, scanErr
		}
		page.Items = append(page.Items, event)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	rows.Close()
	volume, err := service.pool.Query(ctx, `SELECT to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD'),sum(users_synced),sum(groups_synced) FROM tenant.directory_events WHERE `+eventWhere+` GROUP BY 1 ORDER BY 1`, arguments...)
	if err != nil {
		return page, err
	}
	defer volume.Close()
	for volume.Next() {
		var point VolumePoint
		if err := volume.Scan(&point.Date, &point.Users, &point.Groups); err != nil {
			return page, err
		}
		page.Volume = append(page.Volume, point)
	}
	return page, volume.Err()
}

func (handler *Handler) events(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter, err := parseEventFilter(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	page, err := handler.Service.Events(request.Context(), tenantID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}

// Alert is a threshold on a connection's failures.
type Alert struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	ConnectionID *string   `json:"connection_id"`
	Threshold    int       `json:"threshold"`
	Enabled      bool      `json:"enabled"`

	// Read-only: who the alert notifies, and when it was made and last sent.
	UserID         uuid.UUID  `json:"user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	LastNotifiedAt *time.Time `json:"last_notified_at"`
}

// alertUpdate is a PATCH of an alert: each field given is changed. Enabled
// false pauses it; a connection_id of "" makes it cover every connection.
type alertUpdate struct {
	Name         *string `json:"name"`
	ConnectionID *string `json:"connection_id"`
	Threshold    *int    `json:"threshold"`
	Enabled      *bool   `json:"enabled"`
}

const alertColumns = `id,name,connection_id,threshold,enabled,user_id,created_at,last_notified_at`

func scanAlert(row pgx.Row) (Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.Name, &a.ConnectionID, &a.Threshold, &a.Enabled, &a.UserID, &a.CreatedAt, &a.LastNotifiedAt)
	return a, err
}

// knownConnection reports whether id is one of the tenant's connections.
func (handler *Handler) knownConnection(ctx context.Context, tenantID uuid.UUID, id string) (bool, error) {
	connections, err := handler.Service.List(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, connection := range connections {
		if connection.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// recordAlertAudit records an alert change in the tenant's audit log, on tx.
func recordAlertAudit(ctx context.Context, tx pgx.Tx, request *http.Request, tenantID, alertID uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, audit.ActorOf(request).Event(tenantID, action, "directory_alert", alertID, meta))
}

// listAlerts serves GET /tenants/{tenantID}/directory/alerts: every alert of
// the organisation, newest first, with who it notifies.
func (handler *Handler) listAlerts(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	rows, err := handler.Service.pool.Query(request.Context(), `SELECT `+alertColumns+` FROM tenant.directory_alerts WHERE tenant_id=$1 ORDER BY created_at DESC, id`, tenantID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer rows.Close()
	items := []Alert{}
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		items = append(items, alert)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, map[string]any{"items": items})
}

// updateAlert serves PATCH /tenants/{tenantID}/directory/alerts/{alertID}.
func (handler *Handler) updateAlert(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alertID, err := uuid.Parse(chi.URLParam(request, "alertID"))
	if err != nil {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	var in alertUpdate
	if err := httpx.DecodeJSON(request, &in); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		in.Name = &trimmed
	}
	if (in.Name != nil && (len(*in.Name) == 0 || len(*in.Name) > 100)) || (in.Threshold != nil && (*in.Threshold < 1 || *in.Threshold > 100)) {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	if in.ConnectionID != nil && *in.ConnectionID != "" {
		known, err := handler.knownConnection(ctx, tenantID, *in.ConnectionID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		if !known {
			httpx.WriteError(response, request, errs.ErrNotFound)
			return
		}
	}
	tx, err := handler.Service.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer tx.Rollback(ctx)
	alert, err := scanAlert(tx.QueryRow(ctx, `UPDATE tenant.directory_alerts SET
		name = COALESCE($3, name),
		connection_id = CASE WHEN $4::boolean THEN NULLIF($5, '') ELSE connection_id END,
		threshold = COALESCE($6, threshold),
		enabled = COALESCE($7, enabled)
		WHERE tenant_id=$1 AND id=$2 RETURNING `+alertColumns,
		tenantID, alertID, in.Name, in.ConnectionID != nil, in.ConnectionID, in.Threshold, in.Enabled))
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(response, request, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := recordAlertAudit(ctx, tx, request, tenantID, alertID, "directory.alert_updated", map[string]any{
		"name": alert.Name, "connection_id": alert.ConnectionID, "threshold": alert.Threshold, "enabled": alert.Enabled,
	}); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, alert)
}

// deleteAlert serves DELETE /tenants/{tenantID}/directory/alerts/{alertID}.
func (handler *Handler) deleteAlert(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alertID, err := uuid.Parse(chi.URLParam(request, "alertID"))
	if err != nil {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	tx, err := handler.Service.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM tenant.directory_alerts WHERE tenant_id=$1 AND id=$2`, tenantID, alertID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteError(response, request, errs.ErrNotFound)
		return
	}
	if err := recordAlertAudit(ctx, tx, request, tenantID, alertID, "directory.alert_deleted", nil); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) createAlert(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	userID, err := httpx.RequireUser(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	var alert Alert
	if err := httpx.DecodeJSON(request, &alert); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alert.Name = strings.TrimSpace(alert.Name)
	if len(alert.Name) == 0 || len(alert.Name) > 100 || alert.Threshold < 1 || alert.Threshold > 100 {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	if alert.ConnectionID != nil {
		known, err := handler.knownConnection(ctx, tenantID, *alert.ConnectionID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		if !known {
			httpx.WriteError(response, request, errs.ErrNotFound)
			return
		}
	}
	tx, err := handler.Service.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer tx.Rollback(ctx)
	created, err := scanAlert(tx.QueryRow(ctx, `INSERT INTO tenant.directory_alerts(id,tenant_id,user_id,name,connection_id,threshold,enabled)
		VALUES($1,$2,$3,$4,$5,$6,true) RETURNING `+alertColumns, uuid.New(), tenantID, userID, alert.Name, alert.ConnectionID, alert.Threshold))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := recordAlertAudit(ctx, tx, request, tenantID, created.ID, "directory.alert_created", map[string]any{
		"name": created.Name, "connection_id": created.ConnectionID, "threshold": created.Threshold,
	}); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusCreated, created)
}

func (service *Service) notifyAlerts(ctx context.Context, tenantID uuid.UUID, connectionID string) error {
	_, err := service.pool.Exec(ctx, `WITH notified AS (
		UPDATE tenant.directory_alerts SET last_notified_at=NOW()
		WHERE tenant_id=$1 AND enabled AND (connection_id IS NULL OR connection_id=$2)
		AND (last_notified_at IS NULL OR last_notified_at < NOW()-INTERVAL '15 minutes')
		AND threshold <= (SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND status = 'failed' AND started_at >= NOW()-INTERVAL '15 minutes' AND (directory_alerts.connection_id IS NULL OR connection_id=directory_alerts.connection_id))
		RETURNING user_id,name
	) INSERT INTO auth.notifications(user_id,tenant_id,kind,title,description,href)
	SELECT user_id,$1,'warning',name,$3,'/directory/sync-errors' FROM notified`, tenantID, connectionID, "Directory failures reached your alert threshold in the last 15 minutes.")
	return err
}

func (service *Service) enrichConnections(ctx context.Context, tenantID uuid.UUID, records []Connection) error {
	if service.pool == nil {
		return nil
	}
	rows, err := service.pool.Query(ctx, `SELECT DISTINCT ON(connection_id) connection_id,status,started_at,
		(SELECT max(success.started_at) FROM tenant.directory_events success WHERE success.tenant_id=$1 AND success.connection_id=latest.connection_id AND success.status='success' AND success.resource_type <> 'connection')
		FROM tenant.directory_events latest WHERE tenant_id=$1 ORDER BY connection_id,started_at DESC,id DESC`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status string
		var started time.Time
		var successful *time.Time
		if err := rows.Scan(&id, &status, &started, &successful); err != nil {
			return err
		}
		for index := range records {
			if records[index].ID != id {
				continue
			}
			records[index].Health = status
			if status == "success" {
				records[index].Health = "healthy"
			}
			if time.Since(started) > 24*time.Hour {
				records[index].Health = "unknown"
			}
			records[index].LastSyncAt = successful
		}
	}
	return rows.Err()
}
