package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const mappingColumns = `id,source_attribute,target_field,value_type,transform,pattern,enabled,required,version`

var ldapAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9;-]*$`)

func scanMapping(row pgx.Row) (Mapping, error) {
	var mapping Mapping
	err := row.Scan(&mapping.ID, &mapping.Source, &mapping.Target, &mapping.ValueType, &mapping.Transform, &mapping.Pattern, &mapping.Enabled, &mapping.Required, &mapping.Version)
	return mapping, err
}

func (service *Service) Mappings(ctx context.Context, tenantID uuid.UUID, connectionID string) ([]Mapping, error) {
	if tenantID == uuid.Nil || !validConnectionID(tenantID, connectionID) {
		return nil, errs.ErrBadRequest
	}
	rows, err := service.pool.Query(ctx, `SELECT `+mappingColumns+` FROM tenant.directory_mappings WHERE tenant_id=$1 AND connection_id=$2 ORDER BY created_at,id`, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Mapping{}
	for rows.Next() {
		mapping, err := scanMapping(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, mapping)
	}
	return result, rows.Err()
}

func (service *Service) MapProfile(ctx context.Context, tenantID uuid.UUID, connectionID string, source map[string]any, partial bool) (map[string]any, error) {
	mappings, err := service.Mappings(ctx, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	active := false
	for _, mapping := range mappings {
		if mapping.Enabled {
			active = true
			break
		}
	}
	if !active {
		return map[string]any{}, nil
	}
	preview := PreviewMappings(mappings, source, partial)
	if !preview.Valid {
		return nil, errs.ErrBadRequest
	}
	return preview.Profile, nil
}

func (service *Service) SourceAttributes(ctx context.Context, tenantID uuid.UUID, connectionID string) ([]string, error) {
	mappings, err := service.Mappings(ctx, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	attributes := []string{}
	for _, mapping := range mappings {
		if mapping.Enabled && ldapAttributePattern.MatchString(mapping.Source) {
			attributes = append(attributes, mapping.Source)
		}
	}
	return attributes, nil
}

func (service *Service) StoreProfile(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, connectionID string, profile map[string]any) error {
	if tenantID == uuid.Nil || userID == uuid.Nil || !validConnectionID(tenantID, connectionID) {
		return errs.ErrBadRequest
	}
	if len(profile) == 0 {
		return nil
	}
	for field := range profile {
		if _, exists := profileTargets[field]; !exists {
			return errs.ErrBadRequest
		}
	}
	raw, err := json.Marshal(profile)
	if err != nil || len(raw) > 65536 {
		return errs.ErrBadRequest
	}
	_, err = tx.Exec(ctx, `INSERT INTO tenant.directory_profiles(tenant_id,user_id,connection_id,profile) VALUES($1,$2,$3,jsonb_strip_nulls($4::jsonb)) ON CONFLICT(tenant_id,user_id,connection_id) DO UPDATE SET profile=jsonb_strip_nulls(directory_profiles.profile || $4::jsonb),updated_at=NOW()`, tenantID, userID, connectionID, raw)
	if err != nil {
		return err
	}
	if name, exists := profile["display_name"]; exists {
		if name == nil {
			name = ""
		}
		_, err = tx.Exec(ctx, `UPDATE "user".users SET display_name=$3,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenantID, userID, name)
	}
	return err
}

func (handler *Handler) mappingScope(request *http.Request) (uuid.UUID, string, error) {
	tenantID, err := requireTenant(request)
	if err != nil {
		return uuid.Nil, "", err
	}
	connectionID := chi.URLParam(request, "connectionID")
	if !validConnectionID(tenantID, connectionID) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	connections, err := handler.Service.List(request.Context(), tenantID)
	if err != nil {
		return uuid.Nil, "", err
	}
	for _, connection := range connections {
		if connection.ID == connectionID {
			return tenantID, connectionID, nil
		}
	}
	return uuid.Nil, "", errs.ErrNotFound
}

func (handler *Handler) mappings(response http.ResponseWriter, request *http.Request) {
	tenantID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	items, err := handler.Service.Mappings(request.Context(), tenantID, connectionID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, map[string]any{"items": items, "targets": profileTargets})
}

func (handler *Handler) previewMappings(response http.ResponseWriter, request *http.Request) {
	tenantID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 65536)
	var body struct {
		Source map[string]any `json:"source"`
	}
	if err := httpx.DecodeJSON(request, &body); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	items, err := handler.Service.Mappings(request.Context(), tenantID, connectionID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, PreviewMappings(items, body.Source, false))
}

func (handler *Handler) saveMapping(response http.ResponseWriter, request *http.Request) {
	tenantID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 4096)
	var mapping Mapping
	if err := httpx.DecodeJSON(request, &mapping); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := ValidateMapping(mapping); err != nil {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	if !strings.HasPrefix(connectionID, "scim:") && !ldapAttributePattern.MatchString(mapping.Source) {
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID.String()+":"+connectionID); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	status, action := http.StatusCreated, "directory.mapping_created"
	if request.Method == http.MethodPost {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant.directory_mappings WHERE tenant_id=$1 AND connection_id=$2`, tenantID, connectionID).Scan(&count); err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		if count >= 50 {
			httpx.WriteError(response, request, errs.ErrConflict)
			return
		}
		mapping.ID = uuid.New()
		mapping, err = scanMapping(tx.QueryRow(ctx, `INSERT INTO tenant.directory_mappings(id,tenant_id,connection_id,source_attribute,target_field,value_type,transform,pattern,enabled,required) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+mappingColumns, mapping.ID, tenantID, connectionID, mapping.Source, mapping.Target, mapping.ValueType, mapping.Transform, mapping.Pattern, mapping.Enabled, mapping.Required))
	} else {
		mappingID, parseErr := uuid.Parse(chi.URLParam(request, "mappingID"))
		if parseErr != nil || mapping.Version < 1 {
			httpx.WriteError(response, request, errs.ErrBadRequest)
			return
		}
		mapping, err = scanMapping(tx.QueryRow(ctx, `UPDATE tenant.directory_mappings SET source_attribute=$4,target_field=$5,value_type=$6,transform=$7,pattern=$8,enabled=$9,required=$10,version=version+1,updated_at=NOW() WHERE tenant_id=$1 AND connection_id=$2 AND id=$3 AND version=$11 RETURNING `+mappingColumns, tenantID, connectionID, mappingID, mapping.Source, mapping.Target, mapping.ValueType, mapping.Transform, mapping.Pattern, mapping.Enabled, mapping.Required, mapping.Version))
		status, action = http.StatusOK, "directory.mapping_updated"
	}
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &databaseError) && databaseError.Code == "23505") {
			err = errs.ErrConflict
		}
		httpx.WriteError(response, request, err)
		return
	}
	if err := mappingAudit(ctx, tx, request, tenantID, mapping.ID, action); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, status, mapping)
}

func (handler *Handler) deleteMapping(response http.ResponseWriter, request *http.Request) {
	tenantID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	mappingID, err := uuid.Parse(chi.URLParam(request, "mappingID"))
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
	result, err := tx.Exec(ctx, `DELETE FROM tenant.directory_mappings WHERE tenant_id=$1 AND connection_id=$2 AND id=$3`, tenantID, connectionID, mappingID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if result.RowsAffected() == 0 {
		httpx.WriteError(response, request, errs.ErrNotFound)
		return
	}
	if err := mappingAudit(ctx, tx, request, tenantID, mappingID, "directory.mapping_deleted"); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func mappingAudit(ctx context.Context, tx pgx.Tx, request *http.Request, tenantID, mappingID uuid.UUID, action string) error {
	principal := httpx.PrincipalFromCtx(ctx)
	var actor *uuid.UUID
	actorType := "system"
	if principal != nil {
		actor = principal.UserID
		actorType = principal.ActorType
	}
	return audit.Record(ctx, tx, audit.Event{TenantID: &tenantID, ActorUserID: actor, ActorType: actorType, Action: action, ResourceType: "directory_mapping", ResourceID: &mappingID, IP: httpx.ClientIP(request), RequestID: httpx.RequestID(request)})
}
