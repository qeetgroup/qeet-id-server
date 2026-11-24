package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/directory/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

var ldapAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9;-]*$`)

// toMapping is a mapping as its queries return it.
func toMapping(r dbgen.ListDirectoryMappingsRow) Mapping {
	return Mapping{
		ID: r.ID, Source: r.SourceAttribute, Target: r.TargetField, ValueType: r.ValueType, Transform: r.Transform,
		Pattern: r.Pattern, Enabled: r.Enabled, Required: r.Required, Version: int(r.Version),
	}
}

// Mappings returns a connection's mappings.
func (store *Store) Mappings(ctx context.Context, organizationID uuid.UUID, connectionID string) ([]Mapping, error) {
	if organizationID == uuid.Nil || !validConnectionID(organizationID, connectionID) {
		return nil, errs.ErrBadRequest
	}
	rows, err := store.q.ListDirectoryMappings(ctx, dbgen.ListDirectoryMappingsParams{OrganizationID: organizationID, ConnectionID: connectionID})
	if err != nil {
		return nil, err
	}
	result := make([]Mapping, len(rows))
	for i, r := range rows {
		result[i] = toMapping(r)
	}
	return result, nil
}

// MapProfile applies a connection's mappings to source.
func (store *Store) MapProfile(ctx context.Context, organizationID uuid.UUID, connectionID string, source map[string]any, partial bool) (map[string]any, error) {
	mappings, err := store.Mappings(ctx, organizationID, connectionID)
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

// SourceAttributes returns the LDAP attributes the connection's enabled
// mappings read.
func (store *Store) SourceAttributes(ctx context.Context, organizationID uuid.UUID, connectionID string) ([]string, error) {
	mappings, err := store.Mappings(ctx, organizationID, connectionID)
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

// StoreProfile stores a mapped profile on the user.
func (store *Store) StoreProfile(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, connectionID string, profile map[string]any) error {
	if organizationID == uuid.Nil || userID == uuid.Nil || !validConnectionID(organizationID, connectionID) {
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
	q := store.q.WithTx(tx)
	if err := q.UpsertDirectoryProfile(ctx, dbgen.UpsertDirectoryProfileParams{
		OrganizationID: organizationID, UserID: userID, ConnectionID: connectionID, Profile: raw,
	}); err != nil {
		return err
	}
	if name, exists := profile["display_name"]; exists {
		display, _ := name.(string) // a null clears it
		return q.SetMappedDisplayName(ctx, dbgen.SetMappedDisplayNameParams{OrganizationID: &organizationID, ID: userID, DisplayName: &display})
	}
	return nil
}

func (handler *Handler) mappingScope(request *http.Request) (uuid.UUID, string, error) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		return uuid.Nil, "", err
	}
	connectionID := chi.URLParam(request, "connectionID")
	if !validConnectionID(organizationID, connectionID) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	connections, err := handler.Service.List(request.Context(), organizationID)
	if err != nil {
		return uuid.Nil, "", err
	}
	for _, connection := range connections {
		if connection.ID == connectionID {
			return organizationID, connectionID, nil
		}
	}
	return uuid.Nil, "", errs.ErrNotFound
}

func (handler *Handler) mappings(response http.ResponseWriter, request *http.Request) {
	organizationID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	items, err := handler.Service.Mappings(request.Context(), organizationID, connectionID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, mappingList{Result: paging.List(items), Targets: profileTargets})
}

// mappingList is a connection's mappings, with the profile fields they can set.
type mappingList struct {
	paging.Result[Mapping]
	Targets map[string]string `json:"targets"`
}

func (handler *Handler) previewMappings(response http.ResponseWriter, request *http.Request) {
	organizationID, connectionID, err := handler.mappingScope(request)
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
	items, err := handler.Service.Mappings(request.Context(), organizationID, connectionID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defaults, err := handler.Service.defaultAttributes(request.Context(), organizationID, connectionID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	preview := PreviewMappings(items, body.Source, false)
	preview.withDefaults(items, defaults, body.Source)
	httpx.WriteJSON(response, http.StatusOK, preview)
}

// defaultAttributes is where a connection reads a person's email and name
// when no mapping says otherwise: SCIM's userName and displayName, an LDAP
// connection's email and name attributes (mail and cn unless set).
func (service *Service) defaultAttributes(ctx context.Context, organizationID uuid.UUID, connectionID string) (map[string]string, error) {
	if strings.HasPrefix(connectionID, "scim:") {
		return map[string]string{"email": "userName", "display_name": "displayName"}, nil
	}
	sources, err := service.ldap.List(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		if source.ID.String() == connectionID {
			return map[string]string{
				"email":        defaultedAttribute(source.EmailAttribute, "mail"),
				"display_name": defaultedAttribute(source.NameAttribute, "cn"),
			}, nil
		}
	}
	return map[string]string{}, nil
}

func defaultedAttribute(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (handler *Handler) saveMapping(response http.ResponseWriter, request *http.Request) {
	organizationID, connectionID, err := handler.mappingScope(request)
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
		httpx.WriteError(response, request, err)
		return
	}
	if !strings.HasPrefix(connectionID, "scim:") && !ldapAttributePattern.MatchString(mapping.Source) {
		httpx.WriteError(response, request, invalid("source_attribute", CodeMappingSourceInvalid, "source attribute must be an LDAP attribute name").validationError())
		return
	}
	var mappingID uuid.UUID
	status := http.StatusCreated
	if request.Method != http.MethodPost {
		if mappingID, err = httpx.PathUUID(request, "mappingID", errs.ErrBadRequest); err != nil || mapping.Version < 1 {
			httpx.WriteError(response, request, errs.ErrBadRequest)
			return
		}
		status = http.StatusOK
	}
	saved, err := handler.Service.SaveMapping(request.Context(), organizationID, connectionID, mappingID, mapping, audit.ActorOf(request))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, status, saved)
}

// maxMappings is how many mappings one connection holds.
const maxMappings = 50

// SaveMapping adds mapping to the organization's connection or, given a
// mappingID, replaces that one while it is still at mapping.Version, recorded
// as actor's. A connection's changes take turns, so its cap holds.
func (service *Service) SaveMapping(ctx context.Context, organizationID uuid.UUID, connectionID string, mappingID uuid.UUID, mapping Mapping, actor audit.Actor) (Mapping, error) {
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return Mapping{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, organizationID.String()+":"+connectionID); err != nil {
		return Mapping{}, err
	}
	q := service.q.WithTx(tx)
	action := "directory.mapping_created"
	var row dbgen.ListDirectoryMappingsRow
	if mappingID == uuid.Nil {
		var count int64
		if count, err = q.CountDirectoryMappings(ctx, dbgen.CountDirectoryMappingsParams{OrganizationID: organizationID, ConnectionID: connectionID}); err != nil {
			return Mapping{}, err
		}
		if count >= maxMappings {
			return Mapping{}, errs.ErrConflict
		}
		var inserted dbgen.InsertDirectoryMappingRow
		inserted, err = q.InsertDirectoryMapping(ctx, dbgen.InsertDirectoryMappingParams{
			ID: uuid.New(), OrganizationID: organizationID, ConnectionID: connectionID,
			SourceAttribute: mapping.Source, TargetField: mapping.Target, ValueType: mapping.ValueType,
			Transform: mapping.Transform, Pattern: mapping.Pattern, Enabled: mapping.Enabled, Required: mapping.Required,
		})
		row = dbgen.ListDirectoryMappingsRow(inserted)
	} else {
		var updated dbgen.UpdateDirectoryMappingRow
		updated, err = q.UpdateDirectoryMapping(ctx, dbgen.UpdateDirectoryMappingParams{
			OrganizationID: organizationID, ConnectionID: connectionID, ID: mappingID,
			SourceAttribute: mapping.Source, TargetField: mapping.Target, ValueType: mapping.ValueType,
			Transform: mapping.Transform, Pattern: mapping.Pattern, Enabled: mapping.Enabled, Required: mapping.Required,
			Version: int32(mapping.Version), // #nosec G115 -- a version the API returned
		})
		row = dbgen.ListDirectoryMappingsRow(updated)
		action = "directory.mapping_updated"
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || postgres.IsUnique(err) {
			err = errs.ErrConflict
		}
		return Mapping{}, err
	}
	saved := toMapping(row)
	if err := mappingAudit(ctx, tx, actor, organizationID, saved.ID, action); err != nil {
		return Mapping{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Mapping{}, err
	}
	return saved, nil
}

func (handler *Handler) deleteMapping(response http.ResponseWriter, request *http.Request) {
	organizationID, connectionID, err := handler.mappingScope(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	mappingID, err := httpx.PathUUID(request, "mappingID", errs.ErrBadRequest)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := handler.Service.DeleteMapping(request.Context(), organizationID, connectionID, mappingID, audit.ActorOf(request)); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// DeleteMapping removes a mapping of the organization's connection, recorded
// as actor's.
func (service *Service) DeleteMapping(ctx context.Context, organizationID uuid.UUID, connectionID string, mappingID uuid.UUID, actor audit.Actor) error {
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := service.q.WithTx(tx).DeleteDirectoryMapping(ctx, dbgen.DeleteDirectoryMappingParams{
		OrganizationID: organizationID, ConnectionID: connectionID, ID: mappingID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := mappingAudit(ctx, tx, actor, organizationID, mappingID, "directory.mapping_deleted"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// mappingAudit records actor's change to a mapping, on tx.
func mappingAudit(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, mappingID uuid.UUID, action string) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "directory_mapping", mappingID, nil))
}

// Profile is what one connection's mappings set on a person: email,
// display_name, first_name, last_name, department, title, manager_id and
// groups, as the directory last sent them.
type Profile struct {
	ConnectionID   string         `json:"connection_id"`
	ConnectionName string         `json:"connection_name"`
	Fields         map[string]any `json:"fields"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// profiles serves GET /organizations/{organizationID}/directory/profiles/{userID}: the
// person's profile from each connection that set one, newest first. Another
// organization's person has none here.
func (handler *Handler) profiles(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	userID, err := httpx.PathUUID(request, "userID", errs.ErrBadRequest)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	ctx := request.Context()
	rows, err := handler.Service.q.ListDirectoryProfiles(ctx, dbgen.ListDirectoryProfilesParams{OrganizationID: organizationID, UserID: userID})
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	items := make([]Profile, len(rows))
	for i, r := range rows {
		items[i] = Profile{ConnectionID: r.ConnectionID, Fields: map[string]any{}, UpdatedAt: r.UpdatedAt}
		_ = json.Unmarshal(r.Profile, &items[i].Fields)
	}
	if len(items) > 0 {
		connections, err := handler.Service.List(ctx, organizationID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		names := map[string]string{}
		for _, c := range connections {
			names[c.ID] = c.Name
		}
		for i := range items {
			items[i].ConnectionName = names[items[i].ConnectionID]
		}
	}
	httpx.WriteJSON(response, http.StatusOK, paging.List(items))
}
