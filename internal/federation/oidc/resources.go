package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Resource is a downstream service tokens may be issued for (RFC 8707). A token
// for it names it as the only audience. ServerClientID is the application that
// serves it and may introspect its tokens ("" for none).
type Resource struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Identifier     string    `json:"identifier"`
	Name           string    `json:"name"`
	ServerClientID string    `json:"server_client_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func resourceFromRow(r dbgen.AuthOidcResource) Resource {
	out := Resource{ID: r.ID, TenantID: r.TenantID, Identifier: r.Identifier, Name: r.Name, CreatedAt: r.CreatedAt}
	if r.ServerClientID != nil {
		out.ServerClientID = *r.ServerClientID
	}
	return out
}

// wellFormedResource reports an absolute URI without a fragment (RFC 8707 §2).
func wellFormedResource(resource string) bool {
	u, err := url.Parse(resource)
	return err == nil && u.IsAbs() && u.Fragment == ""
}

// checkResource holds a requested resource ("" for none) to the client's
// organisation's registry: anything it hasn't registered is invalid_target. q
// lets it run in the caller's transaction.
func checkResource(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, resource string) error {
	if resource == "" {
		return nil
	}
	if !wellFormedResource(resource) {
		return oauthErr("invalid_target", "resource must be an absolute URI without a fragment")
	}
	ok, err := q.ResourceRegistered(ctx, dbgen.ResourceRegisteredParams{TenantID: tenantID, Identifier: resource})
	if err != nil {
		return err
	}
	if !ok {
		return oauthErr("invalid_target", "resource is not registered for this organisation")
	}
	return nil
}

// ListResources returns an organisation's registered resources.
func (s *Service) ListResources(ctx context.Context, tenantID uuid.UUID) ([]Resource, error) {
	rows, err := s.q.ListResources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Resource, len(rows))
	for i, r := range rows {
		out[i] = resourceFromRow(r)
	}
	return out, nil
}

// CreateResourceInput registers a resource. ServerClientID, when set, must be
// one of the organisation's applications.
type CreateResourceInput struct {
	Identifier     string `json:"identifier"`
	Name           string `json:"name"`
	ServerClientID string `json:"server_client_id"`
}

// CreateResource registers a resource for the organisation.
func (s *Service) CreateResource(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateResourceInput) (*Resource, error) {
	in.Identifier = strings.TrimSpace(in.Identifier)
	if !wellFormedResource(in.Identifier) {
		return nil, errs.ErrOIDCResourceInvalid
	}
	q := s.q.WithTx(tx)
	var server *string
	if in.ServerClientID != "" {
		owner, err := q.GetClientName(ctx, in.ServerClientID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner.TenantID != tenantID) {
			return nil, errs.ErrOIDCClientNotFound
		}
		if err != nil {
			return nil, err
		}
		server = &in.ServerClientID
	}
	row, err := q.InsertResource(ctx, dbgen.InsertResourceParams{
		TenantID: tenantID, Identifier: in.Identifier, Name: strings.TrimSpace(in.Name), ServerClientID: server,
	})
	if pgxerr.IsUnique(err) {
		return nil, errs.ErrOIDCResourceExists
	}
	if err != nil {
		return nil, err
	}
	r := resourceFromRow(row)
	return &r, nil
}

// DeleteResource removes a registered resource; tokens already issued for it
// last out their lifetime, and no new one is issued.
func (s *Service) DeleteResource(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, error) {
	identifier, err := s.q.WithTx(tx).DeleteResource(ctx, dbgen.DeleteResourceParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrOIDCResourceNotFound
	}
	return identifier, err
}

func (h *Handler) listResources(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Service.ListResources(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createResource(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateResourceInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := h.Service.CreateResource(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.auditResource(ctx, tx, r, tenantID, res.ID, "oidc.resource_registered", res.Identifier); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func (h *Handler) deleteResource(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	identifier, err := h.Service.DeleteResource(ctx, tx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.auditResource(ctx, tx, r, tenantID, id, "oidc.resource_removed", identifier); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) auditResource(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, id uuid.UUID, action, identifier string) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	return audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: actorID, ActorType: actorType,
		Action: action, ResourceType: "oidc_resource", ResourceID: &id,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"identifier": identifier},
	})
}
