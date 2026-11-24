package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/directory/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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
	// Reason is the failure's own code, such as ldap.dial_failed, with Params
	// its safe details; Subject the login name a sign-in tried, and UserID the
	// person it was for once known.
	Reason  string            `json:"reason,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Subject string            `json:"subject,omitempty"`
	UserID  *uuid.UUID        `json:"user_id,omitempty"`
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
	paging.Result[Event]
	Total   int           `json:"total"`
	Summary EventSummary  `json:"summary"`
	Volume  []VolumePoint `json:"volume"`
	Limit   int           `json:"limit"`
}

type eventFilter struct {
	Since        time.Time
	ConnectionID string
	Status       string
	Search       string
	Limit        int
	After        paging.Cursor
}

// eventKey is an event's place in the newest-first order its pages follow.
func eventKey(event Event) (time.Time, uuid.UUID) { return event.StartedAt, event.ID }

func classifyOperation(operation string, status int) (outcome, category, code, message, severity string) {
	if status >= 200 && status < 300 {
		return "success", "", "", "Operation completed", ""
	}
	// A person's own credentials refused at sign-in is a sign-in's outcome, not
	// a fault of the connection: a warning, never an open error or an alert.
	if operation == "sign-in" && status == http.StatusUnauthorized {
		return "warning", "credentials", "DIR-401", "The person's directory credentials were refused", ""
	}
	// An owner the LDAP sync kept, as SCIM keeps one, is for an administrator.
	if operation == "sync" && status == http.StatusConflict {
		return "warning", "provisioning", "DIR-409", "The directory disabled or removed an owner of the organization, who keeps their access", ""
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
	case status == http.StatusPreconditionFailed:
		category, message, severity = "provisioning", "The sync stopped without changes: the directory's answer looked incomplete", "critical"
	case status >= 500:
		category, message, severity = "connection", "The directory operation could not be completed", "critical"
	default:
		category, message = "validation", "The directory request could not be validated"
	}
	return outcome, category, "DIR-" + strconv.Itoa(status), message, severity
}

// Operation is one provisioning or directory operation to record. Reason,
// Params, Subject and UserID are as on Event.
type Operation struct {
	OrganizationID uuid.UUID
	ConnectionID   string
	Operation      string
	ResourceType   string
	ResourceID     string
	Status         int
	Started        time.Time
	Duration       time.Duration
	Reason         string
	Params         map[string]string
	Subject        string
	UserID         *uuid.UUID
}

// RecordOperation records one provisioning operation of a connection.
func (store *Store) RecordOperation(ctx context.Context, organizationID uuid.UUID, connectionID, operation, resourceType, resourceID string, status int, started time.Time, duration time.Duration) error {
	return store.Record(ctx, Operation{OrganizationID: organizationID, ConnectionID: connectionID, Operation: operation,
		ResourceType: resourceType, ResourceID: resourceID, Status: status, Started: started, Duration: duration})
}

// RecordLDAPOperation records an LDAP connection's operation.
func (store *Store) RecordLDAPOperation(ctx context.Context, op ldap.Operation) error {
	return store.Record(ctx, Operation{OrganizationID: op.OrganizationID, ConnectionID: op.ConnectionID.String(), Operation: op.Operation,
		ResourceType: op.Resource, Status: op.Status, Started: op.Started, Duration: op.Duration,
		Reason: op.Reason, Params: op.Params, Subject: op.Subject, UserID: op.UserID})
}

// RecordSCIMOperation records a change an organization's identity provider
// sent over SCIM.
func (store *Store) RecordSCIMOperation(ctx context.Context, op scim.Operation) error {
	return store.Record(ctx, Operation{OrganizationID: op.OrganizationID, ConnectionID: "scim:" + op.OrganizationID.String(), Operation: op.Operation,
		ResourceType: op.Resource, ResourceID: op.ResourceID, Status: op.Status, Started: op.Started, Duration: op.Duration,
		Reason: op.Reason})
}

// maxSubjectLen bounds the login name an event keeps.
const maxSubjectLen = 256

// Record records one operation of a connection.
func (store *Store) Record(ctx context.Context, op Operation) error {
	organizationID, connectionID, operation, resourceType, resourceID := op.OrganizationID, op.ConnectionID, op.Operation, op.ResourceType, op.ResourceID
	status, started, duration := op.Status, op.Started, op.Duration
	if organizationID == uuid.Nil || !validConnectionID(organizationID, connectionID) || status < 100 || status > 599 {
		return errs.ErrBadRequest
	}
	if resourceType != "user" && resourceType != "group" && resourceType != "connection" {
		return errs.ErrBadRequest
	}
	if len(resourceID) > 128 {
		resourceID = ""
	}
	subject := op.Subject
	if len(subject) > maxSubjectLen {
		subject = subject[:maxSubjectLen]
	}
	params := op.Params
	if params == nil {
		params = map[string]string{}
	}
	outcome, category, code, message, severity := classifyOperation(operation, status)
	trigger := "manual"
	switch {
	case strings.HasPrefix(connectionID, "scim:"):
		trigger = "push"
	case operation == "sign-in":
		trigger = "sign-in"
	case operation == "sync":
		trigger = "scheduled"
	}
	users, groups := 0, 0
	if outcome == "success" && resourceType == "user" {
		users = 1
	}
	if outcome == "success" && resourceType == "group" {
		groups = 1
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return err
	}
	retryOf, _ := ctx.Value(retryContextKey{}).(uuid.UUID)
	if err := store.q.InsertDirectoryEvent(ctx, dbgen.InsertDirectoryEventParams{
		ID: uuid.New(), OrganizationID: organizationID, ConnectionID: connectionID, Operation: operation,
		TriggerType: trigger, ResourceType: resourceType, ResourceID: resourceID, StartedAt: started.UTC(),
		DurationMs: max(0, duration.Milliseconds()), HttpStatus: int32(status), Status: outcome, // #nosec G115 -- status is 100..599
		UsersSynced: int32(users), GroupsSynced: int32(groups), ErrorCode: code, Message: message, // #nosec G115 -- 0 or 1
		Category: category, Severity: severity, RetryOf: postgres.NullIfZero(retryOf),
		Reason: op.Reason, Params: rawParams, Subject: subject, UserID: op.UserID,
	}); err != nil {
		return err
	}
	if outcome == "failed" {
		return store.notifyAlerts(ctx, organizationID, connectionID)
	}
	if outcome == "success" {
		return store.resolveConnectionFailures(ctx, organizationID, connectionID, operation == "sync" && resourceType == "connection")
	}
	return nil
}

// resolveConnectionFailures marks the connection's open failures of the kind a
// success disproves, the directory unreachable or refusing the connection's
// own credentials (and, once synced, a failed sync), resolved by the system, and audits it
// once. A failure being retried is left for its retry to settle.
func (store *Store) resolveConnectionFailures(ctx context.Context, organizationID uuid.UUID, connectionID string, synced bool) error {
	retrying, _ := ctx.Value(retryContextKey{}).(uuid.UUID)
	// Most successes find nothing to resolve; only then is a transaction opened.
	found, err := store.q.OpenConnectionFailuresExist(ctx, dbgen.OpenConnectionFailuresExistParams{
		OrganizationID: organizationID, ConnectionID: connectionID, Retrying: retrying, Synced: synced,
	})
	if err != nil || !found {
		return err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	resolved, err := store.q.WithTx(tx).ResolveConnectionFailures(ctx, dbgen.ResolveConnectionFailuresParams{
		OrganizationID: organizationID, ConnectionID: connectionID, Retrying: retrying, Synced: synced,
	})
	if err != nil {
		return err
	}
	if len(resolved) == 0 {
		return nil
	}
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, "directory.errors_resolved", "directory_connection", uuid.Nil,
		map[string]any{"connection_id": connectionID, "events": resolved, "reason": "a later operation succeeded"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validConnectionID(organizationID uuid.UUID, connectionID string) bool {
	if connectionID == "scim:"+organizationID.String() {
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
	filter.Limit = paging.Limit(query, filter.Limit, 100)
	after, err := paging.ParseCursor(query)
	if err != nil {
		return filter, err
	}
	filter.After = after
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

const eventColumns = `id,connection_id,operation,trigger_type,resource_type,resource_id,started_at,duration_ms,http_status,status,users_synced,groups_synced,error_code,message,category,severity,resolution,resolved_at,retry_of,reason,params,subject,user_id`
const eventWhere = `organization_id=$1 AND started_at >= $2 AND ($3='' OR connection_id=$3) AND ($4='' OR status=$4) AND ($5='' OR operation ILIKE '%'||$5||'%' OR message ILIKE '%'||$5||'%' OR error_code ILIKE '%'||$5||'%' OR reason ILIKE '%'||$5||'%' OR subject ILIKE '%'||$5||'%')`

func scanEvent(row pgx.Row) (Event, error) {
	var event Event
	err := row.Scan(&event.ID, &event.ConnectionID, &event.Operation, &event.Trigger, &event.ResourceType, &event.ResourceID, &event.StartedAt, &event.DurationMS, &event.HTTPStatus, &event.Status, &event.UsersSynced, &event.GroupsSynced, &event.ErrorCode, &event.Message, &event.Category, &event.Severity, &event.Resolution, &event.ResolvedAt, &event.RetryOf,
		&event.Reason, &event.Params, &event.Subject, &event.UserID)
	if len(event.Params) == 0 {
		event.Params = nil
	}
	event.Retryable = canRetry(event)
	return event, err
}

// Events returns one page of the organization's provisioning events.
func (service *Service) Events(ctx context.Context, organizationID uuid.UUID, filter eventFilter) (EventPage, error) {
	page := EventPage{Result: paging.Page([]Event{}, ""), Volume: []VolumePoint{}, Limit: filter.Limit}
	if organizationID == uuid.Nil {
		return page, errs.ErrUnauthorized
	}
	arguments := []any{organizationID, filter.Since, filter.ConnectionID, filter.Status, postgres.EscapeLike(filter.Search)}
	err := service.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE status='success'),count(*) FILTER(WHERE status='warning'),count(*) FILTER(WHERE status='failed'),round(avg(duration_ms))::bigint FROM organization.directory_events WHERE `+eventWhere, arguments...).Scan(&page.Summary.Total, &page.Summary.Successful, &page.Summary.Warnings, &page.Summary.Failed, &page.Summary.AverageDurationMS)
	if err != nil {
		return page, err
	}
	page.Total = page.Summary.Total
	rows, err := service.pool.Query(ctx, `SELECT `+eventColumns+` FROM organization.directory_events WHERE `+eventWhere+` AND (NOT $7::boolean OR (started_at,id) < ($8::timestamptz,$9::uuid)) ORDER BY started_at DESC,id DESC LIMIT $6`, append(arguments, filter.Limit+1, filter.After.Set, filter.After.Time, filter.After.ID)...)
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
	page.Items, page.NextCursor = paging.Next(page.Items, filter.Limit, eventKey)
	volume, err := service.pool.Query(ctx, `SELECT to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD'),sum(users_synced),sum(groups_synced) FROM organization.directory_events WHERE `+eventWhere+` GROUP BY 1 ORDER BY 1`, arguments...)
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
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter, err := parseEventFilter(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	page, err := handler.Service.Events(request.Context(), organizationID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}
