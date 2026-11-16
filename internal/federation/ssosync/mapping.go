package ssosync

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

const maxMappings = 1000 // group mappings one connection holds

// Mapping maps a group an identity provider asserts through a connection to
// one of the organisation's groups.
type Mapping struct {
	ID        uuid.UUID `json:"id"`
	IdPGroup  string    `json:"idp_group"`
	GroupID   uuid.UUID `json:"group_id"`
	GroupName string    `json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
}

// MappingInput is what CreateMapping takes.
type MappingInput struct {
	IdPGroup string    `json:"idp_group"`
	GroupID  uuid.UUID `json:"group_id"`
}

// Service manages the group mappings of an organisation's SAML and LDAP
// connections.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the mapping service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// connection refuses a connection of kind ("saml" or "ldap") that isn't
// tenantID's with errs.ErrNotFound.
func (s *Service) connection(ctx context.Context, kind string, tenantID, id uuid.UUID) error {
	var found bool
	var err error
	if kind == "saml" {
		found, err = s.q.SAMLConnectionExists(ctx, dbgen.SAMLConnectionExistsParams{ID: id, TenantID: tenantID})
	} else {
		found, err = s.q.LDAPConnectionExists(ctx, dbgen.LDAPConnectionExistsParams{ID: id, TenantID: tenantID})
	}
	if err != nil {
		return err
	}
	if !found {
		return errs.ErrNotFound
	}
	return nil
}

// Mappings returns the group mappings of tenantID's connection.
func (s *Service) Mappings(ctx context.Context, kind string, tenantID, connectionID uuid.UUID) ([]Mapping, error) {
	if err := s.connection(ctx, kind, tenantID, connectionID); err != nil {
		return nil, err
	}
	rows, err := s.q.ListGroupMappings(ctx, dbgen.ListGroupMappingsParams{TenantID: tenantID, ConnectionID: connectionID})
	if err != nil {
		return nil, err
	}
	out := make([]Mapping, len(rows))
	for i, r := range rows {
		out[i] = Mapping{ID: r.ID, IdPGroup: r.IdpGroup, GroupID: r.GroupID, GroupName: r.GroupName, CreatedAt: r.CreatedAt}
	}
	return out, nil
}

// errIdPGroupInvalid refuses an identity provider group that is empty once
// trimmed, or over 1024 bytes.
var errIdPGroupInvalid = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "idp_group", Code: "invalid", Message: "Give the identity provider's group, in up to 1024 characters.",
}})

// checkGroup returns the name of tenantID's group groupID, refusing one that
// isn't the tenant's with errs.ErrGroupNotFound, and one whose roles carry the
// owner role or an administrative permission with
// errs.ErrGroupMappingPrivileged: sign-in never puts anyone in such a group.
func (s *Service) checkGroup(ctx context.Context, tenantID, groupID uuid.UUID) (string, error) {
	g, err := s.q.GroupPrivileged(ctx, dbgen.GroupPrivilegedParams{
		TenantID: tenantID, GroupID: groupID, AdminPermissions: identitylink.AdminPermissions(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrGroupNotFound
	}
	if err != nil {
		return "", err
	}
	if g.Privileged {
		return "", errs.ErrGroupMappingPrivileged
	}
	return g.Name, nil
}

// CreateMapping maps in.IdPGroup to in.GroupID for tenantID's connection, in
// tx. The caller has checked the group with checkGroup and the grant check.
func (s *Service) CreateMapping(ctx context.Context, tx pgx.Tx, tenantID, connectionID uuid.UUID, in MappingInput, groupName string) (*Mapping, error) {
	q := s.q.WithTx(tx)
	n, err := q.CountGroupMappings(ctx, dbgen.CountGroupMappingsParams{TenantID: tenantID, ConnectionID: connectionID})
	if err != nil {
		return nil, err
	}
	if n >= maxMappings {
		return nil, errs.ErrGroupMappingTooMany
	}
	row, err := q.InsertGroupMapping(ctx, dbgen.InsertGroupMappingParams{
		TenantID: tenantID, ConnectionID: connectionID, IdpGroup: in.IdPGroup, GroupID: in.GroupID,
	})
	if pgxerr.IsUnique(err) {
		return nil, errs.ErrGroupMappingExists
	}
	if pgxerr.IsForeignKey(err) {
		return nil, errs.ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Mapping{ID: row.ID, IdPGroup: in.IdPGroup, GroupID: in.GroupID, GroupName: groupName, CreatedAt: row.CreatedAt}, nil
}

// DeleteMapping removes a mapping of tenantID's connection in tx. Once no
// mapping of the connection reaches its group, the memberships of that group
// the connection's sign-ins made end too, each recorded as actor's.
func (s *Service) DeleteMapping(ctx context.Context, tx pgx.Tx, kind string, tenantID, connectionID, mappingID uuid.UUID, actor audit.Actor) (*dbgen.DeleteGroupMappingRow, error) {
	q := s.q.WithTx(tx)
	row, err := q.DeleteGroupMapping(ctx, dbgen.DeleteGroupMappingParams{ID: mappingID, TenantID: tenantID, ConnectionID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	removed, err := q.RemoveUnmappedMemberships(ctx, dbgen.RemoveUnmappedMembershipsParams{TenantID: tenantID, GroupID: row.GroupID, ConnectionID: connectionID})
	if err != nil {
		return nil, err
	}
	for _, userID := range removed {
		if err := recordMembership(ctx, tx, actor, tenantID, row.GroupID, userID, connectionID, kind, "group.member_removed"); err != nil {
			return nil, err
		}
	}
	return &row, nil
}

// Handler serves the group mappings of the organisation's SAML and LDAP
// connections.
type Handler struct {
	Service *Service
	// GrantCheck refuses mapping to a group whose roles carry authority the
	// caller doesn't hold (rbac.Repository.CheckGrantGroup): whoever maps a
	// group hands out what it grants. Without it creating a mapping is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, tenantID, groupID uuid.UUID) error
}

// Mount registers the group-mapping routes of both connection kinds on r.
func (h *Handler) Mount(r chi.Router) {
	for _, kind := range []string{"saml", "ldap"} {
		base := "/tenants/{tenantID}/" + kind + "/{id}/group-mappings"
		r.Get(base, h.list(kind))
		r.Post(base, h.create(kind))
		r.Delete(base+"/{mappingID}", h.del(kind))
	}
}

// scope returns the tenant in the path, which must be the caller's, and the
// connection's ID.
func scope(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	connectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid id")
	}
	return tenantID, connectionID, nil
}

// recordMappingChange audits, in tx, a change to a connection's mappings.
func recordMappingChange(ctx context.Context, tx pgx.Tx, r *http.Request, kind string, tenantID, connectionID uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, audit.ActorOf(r).Event(tenantID, kind+"."+action, kind+"_connection", connectionID, meta))
}

func (h *Handler) list(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, connectionID, err := scope(r)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		items, err := h.Service.Mappings(r.Context(), kind, tenantID, connectionID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(items))
	}
}

func (h *Handler) create(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, connectionID, err := scope(r)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		var in MappingInput
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		in.IdPGroup = strings.TrimSpace(in.IdPGroup)
		if in.IdPGroup == "" || len(in.IdPGroup) > maxGroupValue {
			httpx.WriteError(w, r, errIdPGroupInvalid)
			return
		}
		ctx := r.Context()
		if err := h.Service.connection(ctx, kind, tenantID, connectionID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		groupName, err := h.Service.checkGroup(ctx, tenantID, in.GroupID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if h.GrantCheck == nil {
			httpx.WriteError(w, r, errs.ErrNotImplemented)
			return
		}
		if err := h.GrantCheck(ctx, httpx.PrincipalFromCtx(ctx), tenantID, in.GroupID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		tx, err := h.Service.pool.Begin(ctx)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		defer tx.Rollback(ctx)
		m, err := h.Service.CreateMapping(ctx, tx, tenantID, connectionID, in, groupName)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := recordMappingChange(ctx, tx, r, kind, tenantID, connectionID, "group_mapping_created",
			map[string]any{"mapping_id": m.ID, "idp_group": m.IdPGroup, "group_id": m.GroupID}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, m)
	}
}

func (h *Handler) del(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, connectionID, err := scope(r)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		mappingID, err := uuid.Parse(chi.URLParam(r, "mappingID"))
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid mappingID"))
			return
		}
		ctx := r.Context()
		if err := h.Service.connection(ctx, kind, tenantID, connectionID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		tx, err := h.Service.pool.Begin(ctx)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		defer tx.Rollback(ctx)
		row, err := h.Service.DeleteMapping(ctx, tx, kind, tenantID, connectionID, mappingID, audit.ActorOf(r))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := recordMappingChange(ctx, tx, r, kind, tenantID, connectionID, "group_mapping_deleted",
			map[string]any{"mapping_id": mappingID, "idp_group": row.IdpGroup, "group_id": row.GroupID}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
