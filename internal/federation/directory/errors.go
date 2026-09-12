package directory

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type ErrorSummary struct {
	Open          int  `json:"open"`
	Critical      int  `json:"critical"`
	Warning       int  `json:"warning"`
	Retried       int  `json:"retried"`
	ImpactedUsers *int `json:"impacted_users"`
}

type Breakdown struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type ErrorPage struct {
	Items        []Event      `json:"items"`
	Total        int          `json:"total"`
	Summary      ErrorSummary `json:"summary"`
	Categories   []Breakdown  `json:"categories"`
	Connections  []Breakdown  `json:"connections"`
	Remediations []Event      `json:"remediations"`
	Limit        int          `json:"limit"`
	Offset       int          `json:"offset"`
}

type errorFilter struct {
	eventFilter
	Severity   string
	Resolution string
}

const errorWhere = `tenant_id=$1 AND started_at >= $2 AND ($3='' OR connection_id=$3) AND ($4='' OR severity=$4) AND ($5='' OR resolution=$5) AND ($6='' OR message ILIKE '%'||$6||'%' OR error_code ILIKE '%'||$6||'%' OR resource_id ILIKE '%'||$6||'%') AND status <> 'success'`

func (service *Service) Errors(ctx context.Context, tenantID uuid.UUID, filter errorFilter) (ErrorPage, error) {
	page := ErrorPage{Items: []Event{}, Categories: []Breakdown{}, Connections: []Breakdown{}, Remediations: []Event{}, Limit: filter.Limit, Offset: filter.Offset}
	if tenantID == uuid.Nil || service.pool == nil {
		return page, errs.ErrUnauthorized
	}
	args := []any{tenantID, filter.Since, filter.ConnectionID, filter.Severity, filter.Resolution, filter.Search}
	var impacted, unknown int
	err := service.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE resolution='open'),count(*) FILTER(WHERE resolution='open' AND severity='critical'),count(*) FILTER(WHERE resolution='open' AND severity='warning'),count(*) FILTER(WHERE resolution='retried'),count(DISTINCT NULLIF(resource_id,'')) FILTER(WHERE resource_type='user'),count(*) FILTER(WHERE resource_type='user' AND resource_id='') FROM tenant.directory_events WHERE `+errorWhere, args...).Scan(&page.Total, &page.Summary.Open, &page.Summary.Critical, &page.Summary.Warning, &page.Summary.Retried, &impacted, &unknown)
	if err != nil {
		return page, err
	}
	if unknown == 0 {
		page.Summary.ImpactedUsers = &impacted
	}
	rows, err := service.pool.Query(ctx, `SELECT `+eventColumns+` FROM tenant.directory_events WHERE `+errorWhere+` ORDER BY started_at DESC,id DESC LIMIT $7 OFFSET $8`, append(args, filter.Limit, filter.Offset)...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			rows.Close()
			return page, scanErr
		}
		page.Items = append(page.Items, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	for _, group := range []struct {
		column      string
		destination *[]Breakdown
	}{{"category", &page.Categories}, {"connection_id", &page.Connections}} {
		rows, err := service.pool.Query(ctx, `SELECT `+group.column+`,count(*) FROM tenant.directory_events WHERE `+errorWhere+` GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 20`, args...)
		if err != nil {
			return page, err
		}
		for rows.Next() {
			var item Breakdown
			if err := rows.Scan(&item.Key, &item.Count); err != nil {
				rows.Close()
				return page, err
			}
			*group.destination = append(*group.destination, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return page, err
		}
	}
	rows, err = service.pool.Query(ctx, `SELECT `+eventColumns+` FROM tenant.directory_events WHERE tenant_id=$1 AND resolved_at IS NOT NULL AND ($2='' OR connection_id=$2) ORDER BY resolved_at DESC,id DESC LIMIT 5`, tenantID, filter.ConnectionID)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return page, err
		}
		page.Remediations = append(page.Remediations, event)
	}
	return page, rows.Err()
}

func (handler *Handler) errors(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	base, err := parseEventFilter(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter := errorFilter{eventFilter: base, Severity: request.URL.Query().Get("severity"), Resolution: request.URL.Query().Get("resolution")}
	if filter.Severity != "" && filter.Severity != "warning" && filter.Severity != "critical" {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	if filter.Resolution != "" && filter.Resolution != "open" && filter.Resolution != "resolved" && filter.Resolution != "retried" {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	page, err := handler.Service.Errors(request.Context(), tenantID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}

type retryContextKey struct{}

type LDAPTester interface {
	TestConnection(context.Context, uuid.UUID, uuid.UUID) error
}

func canRetry(event Event) bool {
	return event.Status != "success" && event.Resolution == "open" && event.Operation == "test" && !strings.HasPrefix(event.ConnectionID, "scim:")
}

func recordErrorAudit(ctx context.Context, tx pgx.Tx, request *http.Request, tenantID, eventID uuid.UUID, action string, success bool) error {
	principal := httpx.PrincipalFromCtx(ctx)
	var actor *uuid.UUID
	actorType := "system"
	if principal != nil {
		actor = principal.UserID
		actorType = principal.ActorType
	}
	return audit.Record(ctx, tx, audit.Event{TenantID: &tenantID, ActorUserID: actor, ActorType: actorType, Action: action, ResourceType: "directory_error", ResourceID: &eventID, IP: httpx.ClientIP(request), RequestID: httpx.RequestID(request), Metadata: map[string]any{"success": success}})
}

func (handler *Handler) resolveError(response http.ResponseWriter, request *http.Request) {
	handler.changeError(response, request, false)
}

func (handler *Handler) retryError(response http.ResponseWriter, request *http.Request) {
	handler.changeError(response, request, true)
}

func (handler *Handler) changeError(response http.ResponseWriter, request *http.Request, retry bool) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	eventID, err := uuid.Parse(chi.URLParam(request, "eventID"))
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
	event, err := scanEvent(tx.QueryRow(ctx, `SELECT `+eventColumns+` FROM tenant.directory_events WHERE tenant_id=$1 AND id=$2 AND status <> 'success' FOR UPDATE`, tenantID, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(response, request, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if event.Resolution != "open" {
		httpx.WriteError(response, request, errs.ErrConflict)
		return
	}
	resolution, action, success := "resolved", "directory.error_resolved", true
	if retry {
		tester, ok := handler.Service.ldap.(LDAPTester)
		connectionID, parseErr := uuid.Parse(event.ConnectionID)
		if !ok || parseErr != nil || !canRetry(event) {
			httpx.WriteError(response, request, errs.ErrConflict)
			return
		}
		err = tester.TestConnection(context.WithValue(ctx, retryContextKey{}, eventID), tenantID, connectionID)
		success = err == nil
		resolution, action = "retried", "directory.error_retried"
	}
	if success {
		var actor *uuid.UUID
		if principal := httpx.PrincipalFromCtx(ctx); principal != nil {
			actor = principal.UserID
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant.directory_events SET resolution=$3,resolved_at=NOW(),resolved_by=$4 WHERE tenant_id=$1 AND id=$2`, tenantID, eventID, resolution, actor); err != nil {
			httpx.WriteError(response, request, err)
			return
		}
	}
	if err := recordErrorAudit(ctx, tx, request, tenantID, eventID, action, success); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, map[string]any{"succeeded": success})
}
