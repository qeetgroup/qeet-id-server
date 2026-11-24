package ssosync

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

const maxMappings = 1000 // group mappings one connection holds

// Mapping maps a group an identity provider asserts through a connection to
// one of the organization's groups.
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

// Service manages the group mappings of an organization's SAML and LDAP
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
// organizationID's with errs.ErrNotFound.
func (s *Service) connection(ctx context.Context, kind string, organizationID, id uuid.UUID) error {
	var found bool
	var err error
	if kind == "saml" {
		found, err = s.q.SAMLConnectionExists(ctx, dbgen.SAMLConnectionExistsParams{ID: id, OrganizationID: organizationID})
	} else {
		found, err = s.q.LDAPConnectionExists(ctx, dbgen.LDAPConnectionExistsParams{ID: id, OrganizationID: organizationID})
	}
	if err != nil {
		return err
	}
	if !found {
		return errs.ErrNotFound
	}
	return nil
}

// Mappings returns the group mappings of organizationID's connection.
func (s *Service) Mappings(ctx context.Context, kind string, organizationID, connectionID uuid.UUID) ([]Mapping, error) {
	if err := s.connection(ctx, kind, organizationID, connectionID); err != nil {
		return nil, err
	}
	rows, err := s.q.ListGroupMappings(ctx, dbgen.ListGroupMappingsParams{OrganizationID: organizationID, ConnectionID: connectionID})
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

// checkGroup returns the name of organizationID's group groupID, refusing one that
// isn't the organization's with errs.ErrGroupNotFound, and one whose roles carry the
// owner role or an administrative permission with
// ErrGroupMappingPrivileged: sign-in never puts anyone in such a group.
func (s *Service) checkGroup(ctx context.Context, organizationID, groupID uuid.UUID) (string, error) {
	g, err := s.q.GroupPrivileged(ctx, dbgen.GroupPrivilegedParams{
		OrganizationID: organizationID, GroupID: groupID, MemberPermissions: identitylink.MemberPermissions(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrGroupNotFound
	}
	if err != nil {
		return "", err
	}
	if g.Privileged {
		return "", ErrGroupMappingPrivileged
	}
	return g.Name, nil
}

// CreateMapping maps in.IdPGroup to in.GroupID for organizationID's connection of
// kind, recorded as actor's. The caller has checked the group with checkGroup
// and the grant check.
func (s *Service) CreateMapping(ctx context.Context, kind string, organizationID, connectionID uuid.UUID, in MappingInput, groupName string, actor audit.Actor) (*Mapping, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	n, err := q.CountGroupMappings(ctx, dbgen.CountGroupMappingsParams{OrganizationID: organizationID, ConnectionID: connectionID})
	if err != nil {
		return nil, err
	}
	if n >= maxMappings {
		return nil, ErrGroupMappingTooMany
	}
	row, err := q.InsertGroupMapping(ctx, dbgen.InsertGroupMappingParams{
		OrganizationID: organizationID, ConnectionID: connectionID, IdpGroup: in.IdPGroup, GroupID: in.GroupID,
	})
	if postgres.IsUnique(err) {
		return nil, ErrGroupMappingExists
	}
	if postgres.IsForeignKey(err) {
		return nil, errs.ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	m := &Mapping{ID: row.ID, IdPGroup: in.IdPGroup, GroupID: in.GroupID, GroupName: groupName, CreatedAt: row.CreatedAt}
	if err := recordMappingChange(ctx, tx, actor, kind, organizationID, connectionID, "group_mapping_created",
		map[string]any{"mapping_id": m.ID, "idp_group": m.IdPGroup, "group_id": m.GroupID}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// DeleteMapping removes a mapping of organizationID's connection of kind,
// recorded as actor's. Once no mapping of the connection reaches its group, the
// memberships of that group the connection's sign-ins made end too.
func (s *Service) DeleteMapping(ctx context.Context, kind string, organizationID, connectionID, mappingID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.DeleteGroupMapping(ctx, dbgen.DeleteGroupMappingParams{ID: mappingID, OrganizationID: organizationID, ConnectionID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	removed, err := q.RemoveUnmappedMemberships(ctx, dbgen.RemoveUnmappedMembershipsParams{OrganizationID: organizationID, GroupID: row.GroupID, ConnectionID: connectionID})
	if err != nil {
		return err
	}
	for _, userID := range removed {
		if err := recordMembership(ctx, tx, actor, organizationID, row.GroupID, userID, connectionID, kind, "group.member_removed"); err != nil {
			return err
		}
	}
	if err := recordMappingChange(ctx, tx, actor, kind, organizationID, connectionID, "group_mapping_deleted",
		map[string]any{"mapping_id": mappingID, "idp_group": row.IdpGroup, "group_id": row.GroupID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordMappingChange audits, in tx, actor's change to a connection's mappings.
func recordMappingChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, kind string, organizationID, connectionID uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, kind+"."+action, kind+"_connection", connectionID, meta))
}

func (h *Handler) list(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		organizationID, connectionID, err := scope(r)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		items, err := h.Service.Mappings(r.Context(), kind, organizationID, connectionID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(items))
	}
}

func (h *Handler) create(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		organizationID, connectionID, err := scope(r)
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
		if err := h.Service.connection(ctx, kind, organizationID, connectionID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		groupName, err := h.Service.checkGroup(ctx, organizationID, in.GroupID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if h.GrantCheck == nil {
			httpx.WriteError(w, r, errs.ErrNotImplemented)
			return
		}
		if err := h.GrantCheck(ctx, httpx.PrincipalFromCtx(ctx), organizationID, in.GroupID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		m, err := h.Service.CreateMapping(ctx, kind, organizationID, connectionID, in, groupName, audit.ActorOf(r))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, m)
	}
}

func (h *Handler) del(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		organizationID, connectionID, err := scope(r)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		mappingID, err := httpx.PathUUID(r, "mappingID", errs.ErrBadRequest.WithDetail("invalid mappingID"))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		ctx := r.Context()
		if err := h.Service.connection(ctx, kind, organizationID, connectionID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := h.Service.DeleteMapping(ctx, kind, organizationID, connectionID, mappingID, audit.ActorOf(r)); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
