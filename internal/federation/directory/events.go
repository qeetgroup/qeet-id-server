package directory

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

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

type EventSummary struct {
	Total             int    `json:"total"`
	Successful        int    `json:"successful"`
	Warnings          int    `json:"warnings"`
	Failed            int    `json:"failed"`
	AverageDurationMS *int64 `json:"average_duration_ms"`
}

type VolumePoint struct {
	Date   string `json:"date"`
	Users  int    `json:"users"`
	Groups int    `json:"groups"`
}

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

func (service *Service) SetEventStore(pool *pgxpool.Pool) {
	service.pool = pool
}

func classifyOperation(status int) (outcome, category, code, message, severity string) {
	if status >= 200 && status < 300 {
		return "success", "", "", "Operation completed", ""
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
	outcome, category, code, message, severity := classifyOperation(status)
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
	if outcome != "success" {
		return service.notifyAlerts(ctx, tenantID, connectionID)
	}
	return nil
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

type Alert struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	ConnectionID *string   `json:"connection_id"`
	Threshold    int       `json:"threshold"`
	Enabled      bool      `json:"enabled"`
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
	if alert.ConnectionID != nil {
		connections, err := handler.Service.List(request.Context(), tenantID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		found := false
		for _, connection := range connections {
			if connection.ID == *alert.ConnectionID {
				found = true
			}
		}
		if !found {
			httpx.WriteError(response, request, errs.ErrNotFound)
			return
		}
	}
	alert.ID, alert.Enabled = uuid.New(), true
	_, err = handler.Service.pool.Exec(request.Context(), `INSERT INTO tenant.directory_alerts(id,tenant_id,user_id,name,connection_id,threshold,enabled) VALUES($1,$2,$3,$4,$5,$6,true)`, alert.ID, tenantID, userID, alert.Name, alert.ConnectionID, alert.Threshold)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusCreated, alert)
}

func (service *Service) notifyAlerts(ctx context.Context, tenantID uuid.UUID, connectionID string) error {
	_, err := service.pool.Exec(ctx, `WITH notified AS (
		UPDATE tenant.directory_alerts SET last_notified_at=NOW()
		WHERE tenant_id=$1 AND enabled AND (connection_id IS NULL OR connection_id=$2)
		AND (last_notified_at IS NULL OR last_notified_at < NOW()-INTERVAL '15 minutes')
		AND threshold <= (SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND status <> 'success' AND started_at >= NOW()-INTERVAL '15 minutes' AND (directory_alerts.connection_id IS NULL OR connection_id=directory_alerts.connection_id))
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
