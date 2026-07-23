package oidc

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// OIDC client administration (tenant-scoped CRUD + secret rotation). Every query
// filters by tenant_id so an admin can only see/mutate clients in their own tenant;
// mutations are audited, mirroring registerClient.

// ListClients returns every OIDC client owned by the tenant, newest first.
func (s *Service) ListClients(ctx context.Context, tenantID uuid.UUID) ([]Client, error) {
	rows, err := s.q.ListOIDCClients(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Client, len(rows))
	for i, r := range rows {
		out[i] = Client{
			ID: r.ID, TenantID: r.TenantID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
			RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
			GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
		}
	}
	return out, nil
}

// GetClient resolves a single client by row id within the tenant.
func (s *Service) GetClient(ctx context.Context, tenantID, id uuid.UUID) (*Client, error) {
	r, err := s.q.GetOIDCClient(ctx, dbgen.GetOIDCClientParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := Client{
		ID: r.ID, TenantID: r.TenantID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
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
	// *[]string → []string: nil pointer → nil slice (SQL NULL → COALESCE keeps existing).
	var redirectUris, postLogoutUris, grantTypes, scopes []string
	if in.RedirectURIs != nil {
		redirectUris = *in.RedirectURIs
	}
	if in.PostLogoutURIs != nil {
		postLogoutUris = *in.PostLogoutURIs
	}
	if in.GrantTypes != nil {
		grantTypes = *in.GrantTypes
	}
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	q := s.q.WithTx(tx)
	r, err := q.UpdateOIDCClient(ctx, dbgen.UpdateOIDCClientParams{
		Name:           in.Name,
		RedirectUris:   redirectUris,
		PostLogoutUris: postLogoutUris,
		GrantTypes:     grantTypes,
		Scopes:         scopes,
		ID:             id,
		TenantID:       tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := Client{
		ID: r.ID, TenantID: r.TenantID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
	}
	return &c, nil
}

// DeleteClient removes a tenant's client. Returns the public client_id (for the
// audit row) or ErrNotFound if the row doesn't exist in this tenant.
func (s *Service) DeleteClient(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, error) {
	q := s.q.WithTx(tx)
	clientID, err := q.DeleteOIDCClient(ctx, dbgen.DeleteOIDCClientParams{ID: id, TenantID: tenantID})
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
	q := s.q.WithTx(tx)
	r, err := q.LockOIDCClientForUpdate(ctx, dbgen.LockOIDCClientForUpdateParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, errs.ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	if r.Type != "confidential" {
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
	if err := q.UpdateOIDCClientSecret(ctx, dbgen.UpdateOIDCClientSecretParams{
		ClientSecretHash: &hash, ID: id, TenantID: tenantID,
	}); err != nil {
		return "", nil, err
	}
	c := Client{
		ID: r.ID, TenantID: r.TenantID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
	}
	return secret, &c, nil
}

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

// rotateKey generates a new EC P-256 signing key and retires the current active
// key to verify-only. The new private key PEM is returned once in the response
// body — the operator must save it as JWT_SIGNING_KEY before the next restart.
// This is a platform-level (non-tenant-scoped) operator action and is audited.
func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	privPEM, kid, err := h.Service.issuer.Rotate()
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
	actorID, actorType := auditActor(r)
	if err := audit.Record(ctx, tx, audit.Event{
		ActorUserID: actorID, ActorType: actorType,
		Action: "oidc.signing_key_rotated", ResourceType: "signing_key", ResourceID: nil,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"new_kid": kid},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"kid":             kid,
		"alg":             "ES256",
		"private_key_pem": privPEM,
		"warning":         "Save this PEM as JWT_SIGNING_KEY immediately — it will not be shown again.",
	})
}

func (h *Handler) shadowAI(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ShadowAICandidates(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) reviewShadowAI(w http.ResponseWriter, r *http.Request) {
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
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("review must be attributed to a human"))
		return
	}
	if err := h.Service.ReviewShadowAIClient(r.Context(), tenantID, id, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
