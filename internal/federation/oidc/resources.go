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
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Resource is a downstream service tokens may be issued for (RFC 8707). A token
// for it names it as the only audience. ServerClientID is the application that
// serves it and may introspect its tokens ("" for none).
type Resource struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Identifier     string    `json:"identifier"`
	Name           string    `json:"name"`
	ServerClientID string    `json:"server_client_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func resourceFromRow(r dbgen.AuthOidcResource) Resource {
	out := Resource{ID: r.ID, OrganizationID: r.OrganizationID, Identifier: r.Identifier, Name: r.Name, CreatedAt: r.CreatedAt}
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
// organization's registry: anything it hasn't registered is invalid_target. q
// lets it run in the caller's transaction.
func checkResource(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, resource string) error {
	if resource == "" {
		return nil
	}
	if !wellFormedResource(resource) {
		return oauthErr("invalid_target", "resource must be an absolute URI without a fragment")
	}
	ok, err := q.ResourceRegistered(ctx, dbgen.ResourceRegisteredParams{OrganizationID: organizationID, Identifier: resource})
	if err != nil {
		return err
	}
	if !ok {
		return oauthErr("invalid_target", "resource is not registered for this organization")
	}
	return nil
}

// ListResources returns an organization's registered resources.
func (s *Service) ListResources(ctx context.Context, organizationID uuid.UUID) ([]Resource, error) {
	rows, err := s.q.ListResources(ctx, organizationID)
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
// one of the organization's applications.
type CreateResourceInput struct {
	Identifier     string `json:"identifier"`
	Name           string `json:"name"`
	ServerClientID string `json:"server_client_id"`
}

// CheckResourceDomain refuses a resource identifier naming the platform (ErrOIDCResourceReserved: its
// issuer, audience, their hosts or publicBaseURL's), one on a domain another organization verified
// (ErrOIDCResourceDomainTaken), or one on a host, or a domain above it, this organization hasn't
// (ErrOIDCResourceDomainUnverified). It reads every organization's domains, so runs before the tx.
func (s *Service) CheckResourceDomain(ctx context.Context, organizationID uuid.UUID, identifier, publicBaseURL string) error {
	identifier = strings.TrimSpace(identifier)
	host := hostOf(identifier)
	for _, own := range []string{s.issuer.JWTIssuer(), s.issuer.JWTAudience(), publicBaseURL} {
		if own != "" && (identifier == own || (host != "" && host == hostOf(own))) {
			return ErrResourceReserved
		}
	}
	if host == "" {
		return nil
	}
	taken, err := s.q.ResourceHostClaimedElsewhere(postgres.AcrossOrganizations(ctx), dbgen.ResourceHostClaimedElsewhereParams{OrganizationID: organizationID, Host: host})
	if err != nil {
		return err
	}
	if taken {
		return ErrResourceDomainTaken
	}
	verified, err := s.q.ResourceHostVerifiedHere(ctx, dbgen.ResourceHostVerifiedHereParams{OrganizationID: organizationID, Host: host})
	if err != nil {
		return err
	}
	if !verified {
		return ErrResourceDomainUnverified
	}
	return nil
}

// hostOf is the lower-case host of an absolute URI, or "" for none.
func hostOf(uri string) string {
	if u, err := url.Parse(uri); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// CreateResource registers a resource for the organization, recorded as
// actor's. An identifier is unique across the platform (ErrOIDCResourceExists);
// callers check its domain first with CheckResourceDomain.
func (s *Service) CreateResource(ctx context.Context, organizationID uuid.UUID, in CreateResourceInput, actor audit.Actor) (*Resource, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	res, err := s.createResource(ctx, tx, organizationID, in)
	if err != nil {
		return nil, err
	}
	if err := recordResourceChange(ctx, tx, actor, organizationID, res.ID, "oidc.resource_registered", res.Identifier); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// createResource registers a resource for the organization within tx.
func (s *Service) createResource(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, in CreateResourceInput) (*Resource, error) {
	in.Identifier = strings.TrimSpace(in.Identifier)
	if !wellFormedResource(in.Identifier) {
		return nil, ErrResourceInvalid
	}
	q := s.q.WithTx(tx)
	var server *string
	if in.ServerClientID != "" {
		owner, err := q.GetClientName(ctx, in.ServerClientID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner.OrganizationID != organizationID) {
			return nil, ErrClientNotFound
		}
		if err != nil {
			return nil, err
		}
		server = &in.ServerClientID
	}
	row, err := q.InsertResource(ctx, dbgen.InsertResourceParams{
		OrganizationID: organizationID, Identifier: in.Identifier, Name: strings.TrimSpace(in.Name), ServerClientID: server,
	})
	if postgres.IsUnique(err) {
		return nil, ErrResourceExists
	}
	if err != nil {
		return nil, err
	}
	r := resourceFromRow(row)
	return &r, nil
}

// DeleteResource removes a registered resource, recorded as actor's; tokens
// already issued for it last out their lifetime, and no new one is issued.
func (s *Service) DeleteResource(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	identifier, err := s.q.WithTx(tx).DeleteResource(ctx, dbgen.DeleteResourceParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if err := recordResourceChange(ctx, tx, actor, organizationID, id, "oidc.resource_removed", identifier); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordResourceChange audits, in tx, actor's change to organizationID's
// resource id.
func recordResourceChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action, identifier string) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "oidc_resource", id, map[string]any{"identifier": identifier}))
}

func (h *Handler) listResources(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Service.ListResources(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

func (h *Handler) createResource(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
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
	if err := h.Service.CheckResourceDomain(ctx, organizationID, in.Identifier, h.PublicBaseURL); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.CreateResource(ctx, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func (h *Handler) deleteResource(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteResource(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
