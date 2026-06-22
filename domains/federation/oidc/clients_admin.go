package oidc

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/codes"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/password"
)

// =====================================================================
// OIDC client administration (tenant-scoped CRUD + secret rotation)
//
// Every query is filtered by tenant_id so an admin can only ever see or
// mutate clients in their own tenant. Mutations are audited, mirroring the
// registration audit row in registerClient.
// =====================================================================

// clientColumns is the SELECT/RETURNING projection shared by every read so the
// scan order matches the Client struct exactly. The client_secret_hash is
// deliberately never selected.
const clientColumns = `id, tenant_id, client_id, type, name, redirect_uris,
	post_logout_uris, grant_types, scopes, created_at`

func scanClient(row pgx.Row, c *Client) error {
	return row.Scan(&c.ID, &c.TenantID, &c.ClientID, &c.Type, &c.Name,
		&c.RedirectURIs, &c.PostLogoutURIs, &c.GrantTypes, &c.Scopes, &c.CreatedAt)
}

// ListClients returns every OIDC client owned by the tenant, newest first.
func (s *Service) ListClients(ctx context.Context, tenantID uuid.UUID) ([]Client, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+clientColumns+`
		FROM auth.oidc_clients
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err := scanClient(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetClient resolves a single client by row id within the tenant. The id may be
// either the row UUID or the public client_id (the admin detail page links by
// the public client_id), so we match on both.
func (s *Service) GetClient(ctx context.Context, tenantID, id uuid.UUID) (*Client, error) {
	var c Client
	err := scanClient(s.pool.QueryRow(ctx, `
		SELECT `+clientColumns+`
		FROM auth.oidc_clients
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID), &c)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateClientInput is a partial (COALESCE-style) update: a nil field is left
// unchanged, so the admin UI can PATCH only what changed.
type UpdateClientInput struct {
	Name           *string   `json:"name"`
	RedirectURIs   *[]string `json:"redirect_uris"`
	PostLogoutURIs *[]string `json:"post_logout_uris"`
	GrantTypes     *[]string `json:"grant_types"`
	Scopes         *[]string `json:"scopes"`
}

// UpdateClient applies a partial update to a tenant's client and returns the
// updated row. Unset (nil) fields are preserved via COALESCE. type and
// client_id are immutable here (rotate-secret handles credentials).
func (s *Service) UpdateClient(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, in UpdateClientInput) (*Client, error) {
	var c Client
	err := scanClient(tx.QueryRow(ctx, `
		UPDATE auth.oidc_clients SET
			name             = COALESCE($3, name),
			redirect_uris    = COALESCE($4, redirect_uris),
			post_logout_uris = COALESCE($5, post_logout_uris),
			grant_types      = COALESCE($6, grant_types),
			scopes           = COALESCE($7, scopes)
		WHERE id = $1 AND tenant_id = $2
		RETURNING `+clientColumns+`
	`, id, tenantID, in.Name, in.RedirectURIs, in.PostLogoutURIs, in.GrantTypes, in.Scopes), &c)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// DeleteClient removes a tenant's client. Returns the public client_id (for the
// audit row) or ErrNotFound if the row doesn't exist in this tenant.
func (s *Service) DeleteClient(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, error) {
	var clientID string
	err := tx.QueryRow(ctx, `
		DELETE FROM auth.oidc_clients WHERE id = $1 AND tenant_id = $2 RETURNING client_id
	`, id, tenantID).Scan(&clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return clientID, nil
}

// RotateClientSecret mints a fresh client secret for a confidential client,
// re-using the SAME generation + hashing as RegisterClient, stores only the
// hash, and returns the plaintext once. Public clients have no secret, so the
// rotation is rejected with a 422. Tenant-scoped.
func (s *Service) RotateClientSecret(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, *Client, error) {
	var c Client
	if err := scanClient(tx.QueryRow(ctx, `
		SELECT `+clientColumns+`
		FROM auth.oidc_clients
		WHERE id = $1 AND tenant_id = $2
		FOR UPDATE
	`, id, tenantID), &c); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, errs.ErrNotFound
		}
		return "", nil, err
	}
	if c.Type != "confidential" {
		return "", nil, errs.ErrUnprocessable.WithDetail("public clients have no secret to rotate")
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return "", nil, err
	}
	hash, err := password.Hash(secret)
	if err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.oidc_clients SET client_secret_hash = $3 WHERE id = $1 AND tenant_id = $2
	`, id, tenantID, hash); err != nil {
		return "", nil, err
	}
	return secret, &c, nil
}

// =====================================================================
// HTTP handlers
// =====================================================================

// auditActor resolves the (actorID, actorType) for an audit row from the
// request principal, mirroring registerClient/revokeGrant.
func auditActor(r *http.Request) (*uuid.UUID, string) {
	actorType := "system"
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		} else {
			actorType = "user"
		}
	}
	return actorID, actorType
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid id")
	}
	return id, nil
}

// createTenantClient registers a client under the path tenant. It overrides any
// tenant_id in the body with the path/JWT tenant so a client can't be created
// in another tenant. Mirrors registerClient's audit + one-time-secret response.
func (h *Handler) createTenantClient(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID // path/JWT tenant wins over the body
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	c, secret, err := h.Service.RegisterClient(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oidc.client_registered", ResourceType: "oidc_client", ResourceID: &resourceID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{
			"client_id": c.ClientID, "type": c.Type, "name": c.Name,
			"grant_types": c.GrantTypes, "scopes": c.Scopes,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp := map[string]any{"client": c}
	if secret != "" {
		resp["client_secret"] = secret
		resp["warning"] = "secret shown once"
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (h *Handler) listClients(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListClients(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) getClient(w http.ResponseWriter, r *http.Request) {
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
	c, err := h.Service.GetClient(r.Context(), tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *Handler) patchClient(w http.ResponseWriter, r *http.Request) {
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
	var in UpdateClientInput
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
	c, err := h.Service.UpdateClient(ctx, tx, tenantID, id, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oidc.client_updated", ResourceType: "oidc_client", ResourceID: &resourceID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": c.ClientID, "name": c.Name},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
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
	h.deleteClientInTenant(w, r, tenantID, id)
}

// deleteClientByScope serves the admin UI's non-tenant-scoped
// DELETE /v1/oidc/clients/{id}: it derives the tenant from the caller's JWT so
// the delete is still strictly tenant-scoped.
func (h *Handler) deleteClientByScope(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deleteClientInTenant(w, r, tenantID, id)
}

// deleteClientInTenant performs the audited, tenant-scoped delete shared by the
// tenant-path and JWT-scoped delete handlers.
func (h *Handler) deleteClientInTenant(w http.ResponseWriter, r *http.Request, tenantID, id uuid.UUID) {
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	clientID, err := h.Service.DeleteClient(ctx, tx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := tenantID
	resourceID := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oidc.client_deleted", ResourceType: "oidc_client", ResourceID: &resourceID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": clientID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
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
	secret, c, err := h.Service.RotateClientSecret(ctx, tx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oidc.client_secret_rotated", ResourceType: "oidc_client", ResourceID: &resourceID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": c.ClientID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_secret": secret,
		"warning":       "secret shown once",
	})
}

// signingKeys reports the issuer's signing-key metadata (active + retired). The
// signing key is global/issuer-level, not per-tenant, so this endpoint is not
// tenant-scoped; it exposes no key material (see Issuer.KeyInfo).
func (h *Handler) signingKeys(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": h.Service.issuer.KeyInfo()})
}
