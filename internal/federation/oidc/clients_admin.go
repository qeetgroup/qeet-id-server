package oidc

import (
	"time"

	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// OIDC client administration (organization-scoped CRUD + secret rotation). Every query
// filters by organization_id so an admin can only see/mutate clients in their own organization;
// mutations are audited, mirroring registerClient.

// ListClients returns every OIDC client owned by the organization, newest first.
func (s *Service) ListClients(ctx context.Context, organizationID uuid.UUID) ([]Client, error) {
	rows, err := s.q.ListOIDCClients(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Client, len(rows))
	for i, r := range rows {
		out[i] = Client{
			ID: r.ID, OrganizationID: r.OrganizationID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
			RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
			GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
			PKCEExemptUntil:      r.PkceExemptUntil,
			BackchannelLogoutURI: strutil.Deref(r.BackchannelLogoutUri), FrontchannelLogoutURI: strutil.Deref(r.FrontchannelLogoutUri),
			LogoURI: strutil.Deref(r.LogoUri), ClientURI: strutil.Deref(r.ClientUri),
		}
	}
	if err := s.clientWebOrigins(ctx, organizationID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetClient resolves a single client by row id within the organization.
func (s *Service) GetClient(ctx context.Context, organizationID, id uuid.UUID) (*Client, error) {
	r, err := s.q.GetOIDCClient(ctx, dbgen.GetOIDCClientParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	c := Client{
		ID: r.ID, OrganizationID: r.OrganizationID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
		PKCEExemptUntil:      r.PkceExemptUntil,
		BackchannelLogoutURI: strutil.Deref(r.BackchannelLogoutUri), FrontchannelLogoutURI: strutil.Deref(r.FrontchannelLogoutUri),
		LogoURI: strutil.Deref(r.LogoUri), ClientURI: strutil.Deref(r.ClientUri),
	}
	stored, err := s.q.GetClientWebOrigins(ctx, dbgen.GetClientWebOriginsParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	c.WebOrigins = effectiveWebOrigins(c.RedirectURIs, stored)
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
	// PKCEExemptUntil sets (a time) or clears (null) a confidential
	// application's exemption from sending a PKCE code_challenge and a nonce,
	// ending within 90 days.
	PKCEExemptUntil OptionalTime `json:"pkce_exempt_until"`
	// BackchannelLogoutURI and FrontchannelLogoutURI set where the application
	// hears of a sign-out ("" clears; nil: unchanged).
	BackchannelLogoutURI  *string `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI *string `json:"frontchannel_logout_uri"`
	// LogoURI and ClientURI set the application's logo and home page ("" clears;
	// nil: unchanged).
	LogoURI   *string `json:"logo_uri"`
	ClientURI *string `json:"client_uri"`
	// WebOrigins sets the origins a browser application calls from (null:
	// its redirect URIs' origins; left out: unchanged).
	WebOrigins OptionalOrigins `json:"web_origins"`
}

// UpdateClient applies a partial update to an organization's client, recorded as
// actor's, and returns the updated row.
func (s *Service) UpdateClient(ctx context.Context, organizationID, id uuid.UUID, in UpdateClientInput, actor audit.Actor) (*Client, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c, err := s.updateClient(ctx, tx, organizationID, id, in)
	if err != nil {
		return nil, err
	}
	if err := recordClientChange(ctx, tx, actor, c, "oidc.client_updated", clientUpdatedMeta(c, in)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// updateClient applies a partial update to an organization's client in tx and
// returns the updated row. Unset (nil) fields are preserved via COALESCE. type
// and client_id are immutable here (rotate-secret handles credentials).
func (s *Service) updateClient(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, in UpdateClientInput) (*Client, error) {
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
	// Hold the edited client to the same rules as registration, checked on the
	// result of the edit (unset fields keep their stored values).
	cur, err := q.GetOIDCClient(ctx, dbgen.GetOIDCClientParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	merged := CreateClientInput{Type: cur.Type, RedirectURIs: cur.RedirectUris, PostLogoutURIs: cur.PostLogoutUris, GrantTypes: cur.GrantTypes}
	if in.RedirectURIs != nil {
		merged.RedirectURIs = redirectUris
	}
	if in.PostLogoutURIs != nil {
		merged.PostLogoutURIs = postLogoutUris
	}
	if in.GrantTypes != nil {
		merged.GrantTypes = grantTypes
	}
	if err := validateClientInput(merged); err != nil {
		return nil, err
	}
	if in.PKCEExemptUntil.Set {
		if err := validPKCEExemption(cur.Type, in.PKCEExemptUntil.At, time.Now()); err != nil {
			return nil, err
		}
	}
	for _, u := range []*string{in.BackchannelLogoutURI, in.FrontchannelLogoutURI} {
		if u != nil && !validLogoutURI(*u) {
			return nil, errs.ErrBadRequest.WithDetail("logout URIs must be absolute http(s) URLs without a fragment")
		}
	}
	for _, u := range []*string{in.LogoURI, in.ClientURI} {
		if u != nil && !validPresentationURI(*u) {
			return nil, errs.ErrBadRequest.WithDetail(presentationURIRule)
		}
	}
	r, err := q.UpdateOIDCClient(ctx, dbgen.UpdateOIDCClientParams{
		Name:                     in.Name,
		RedirectUris:             redirectUris,
		PostLogoutUris:           postLogoutUris,
		GrantTypes:               grantTypes,
		Scopes:                   scopes,
		SetPkceExemptUntil:       in.PKCEExemptUntil.Set,
		PkceExemptUntil:          in.PKCEExemptUntil.At,
		SetBackchannelLogoutUri:  in.BackchannelLogoutURI != nil,
		BackchannelLogoutUri:     strutil.Deref(in.BackchannelLogoutURI),
		SetFrontchannelLogoutUri: in.FrontchannelLogoutURI != nil,
		FrontchannelLogoutUri:    strutil.Deref(in.FrontchannelLogoutURI),
		SetLogoUri:               in.LogoURI != nil,
		LogoUri:                  strutil.Deref(in.LogoURI),
		SetClientUri:             in.ClientURI != nil,
		ClientUri:                strutil.Deref(in.ClientURI),
		ID:                       id,
		OrganizationID:           organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	c := Client{
		ID: r.ID, OrganizationID: r.OrganizationID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
		PKCEExemptUntil:      r.PkceExemptUntil,
		BackchannelLogoutURI: strutil.Deref(r.BackchannelLogoutUri), FrontchannelLogoutURI: strutil.Deref(r.FrontchannelLogoutUri),
		LogoURI: strutil.Deref(r.LogoUri), ClientURI: strutil.Deref(r.ClientUri),
	}
	if in.WebOrigins.Set {
		if err := s.setWebOrigins(ctx, tx, organizationID, id, in.WebOrigins.Origins); err != nil {
			return nil, err
		}
	} else if in.RedirectURIs != nil {
		s.webOrigins.forget()
	}
	stored, err := q.GetClientWebOrigins(ctx, dbgen.GetClientWebOriginsParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	c.WebOrigins = effectiveWebOrigins(c.RedirectURIs, stored)
	return &c, nil
}

// DeleteClient removes an organization's client, recorded as actor's, or
// refuses with ErrClientNotFound if the row doesn't exist in this organization.
func (s *Service) DeleteClient(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	clientID, err := s.q.WithTx(tx).DeleteOIDCClient(ctx, dbgen.DeleteOIDCClientParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrClientNotFound
	}
	if err != nil {
		return err
	}
	if err := recordClientChange(ctx, tx, actor, &Client{ID: id, OrganizationID: organizationID}, "oidc.client_deleted",
		map[string]any{"client_id": clientID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RotateClientSecret mints a fresh client secret for a confidential client,
// recorded as actor's, and returns the plaintext once. Organization-scoped.
func (s *Service) RotateClientSecret(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	secret, c, err := s.rotateClientSecret(ctx, tx, organizationID, id)
	if err != nil {
		return "", err
	}
	if err := recordClientChange(ctx, tx, actor, c, "oidc.client_secret_rotated", map[string]any{"client_id": c.ClientID}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return secret, nil
}

// rotateClientSecret mints a fresh client secret in tx, re-using the SAME
// generation + hashing as RegisterClient, stores only the hash, and returns
// the plaintext once. Public clients have no secret, so the rotation is
// rejected with a 422.
func (s *Service) rotateClientSecret(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (string, *Client, error) {
	q := s.q.WithTx(tx)
	r, err := q.LockOIDCClientForUpdate(ctx, dbgen.LockOIDCClientForUpdateParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrClientNotFound
	}
	if err != nil {
		return "", nil, err
	}
	if r.Type != "confidential" {
		return "", nil, ErrPublicClientNoSecret
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return "", nil, err
	}
	hash := password.HashSecret(secret)
	if err := q.UpdateOIDCClientSecret(ctx, dbgen.UpdateOIDCClientSecretParams{
		ClientSecretHash: &hash, ID: id, OrganizationID: organizationID,
	}); err != nil {
		return "", nil, err
	}
	c := Client{
		ID: r.ID, OrganizationID: r.OrganizationID, ClientID: r.ClientID, Type: r.Type, Name: r.Name,
		RedirectURIs: r.RedirectUris, PostLogoutURIs: r.PostLogoutUris,
		GrantTypes: r.GrantTypes, Scopes: r.Scopes, CreatedAt: r.CreatedAt,
		PKCEExemptUntil:      r.PkceExemptUntil,
		BackchannelLogoutURI: strutil.Deref(r.BackchannelLogoutUri), FrontchannelLogoutURI: strutil.Deref(r.FrontchannelLogoutUri),
		LogoURI: strutil.Deref(r.LogoUri), ClientURI: strutil.Deref(r.ClientUri),
	}
	return secret, &c, nil
}

func pathID(r *http.Request) (uuid.UUID, error) {
	return httpx.PathUUID(r, "id", ErrIDInvalid)
}

// createOrganizationClient registers a client under the path organization. It overrides any
// organization_id in the body with the path/JWT organization so a client can't be created
// in another organization. Mirrors registerClient's audit + one-time-secret response.
func (h *Handler) createOrganizationClient(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = organizationID // path/JWT organization wins over the body
	c, secret, err := h.Service.CreateClient(r.Context(), in, audit.ActorOf(r))
	if err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListClients(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) getClient(w http.ResponseWriter, r *http.Request) {
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
	c, err := h.Service.GetClient(r.Context(), organizationID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

// clientAuthFailures is an application's lockout in force (if any) and its
// recent wrong-secret attempts, with time and address, never the secret.
func (h *Handler) clientAuthFailures(w http.ResponseWriter, r *http.Request) {
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
	out, err := h.Service.RecentClientAuthFailures(r.Context(), organizationID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) patchClient(w http.ResponseWriter, r *http.Request) {
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
	var in UpdateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	c, err := h.Service.UpdateClient(r.Context(), organizationID, id, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
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
	h.deleteClientInOrganization(w, r, organizationID, id)
}

// deleteClientByScope serves the admin UI's non-organization-scoped
// DELETE /v1/oidc/clients/{id}: it derives the organization from the caller's JWT so
// the delete is still strictly organization-scoped.
func (h *Handler) deleteClientByScope(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deleteClientInOrganization(w, r, organizationID, id)
}

// deleteClientInOrganization performs the audited, organization-scoped delete shared by the
// organization-path and JWT-scoped delete handlers.
func (h *Handler) deleteClientInOrganization(w http.ResponseWriter, r *http.Request, organizationID, id uuid.UUID) {
	if err := h.Service.DeleteClient(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
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
	secret, err := h.Service.RotateClientSecret(r.Context(), organizationID, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_secret": secret,
		"warning":       "secret shown once",
	})
}

// SigningKey is a signing key's metadata with when the registry created and
// activated it; both nil for a key it doesn't hold (one from configuration).
type SigningKey struct {
	tokens.KeyMeta
	CreatedAt   *time.Time `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at"`
}

// SigningKeys returns the issuer's signing-key metadata (see Issuer.KeyInfo),
// dated from the key registry.
func (s *Service) SigningKeys(ctx context.Context) ([]SigningKey, error) {
	keys := s.issuer.KeyInfo()
	dates := make(map[string][2]*time.Time, len(keys))
	rows, err := s.q.ListSigningKeyDates(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		dates[r.Kid] = [2]*time.Time{&r.CreatedAt, r.ActivatedAt}
	}
	out := make([]SigningKey, len(keys))
	for i, k := range keys {
		d := dates[k.Kid]
		out[i] = SigningKey{KeyMeta: k, CreatedAt: d[0], ActivatedAt: d[1]}
	}
	return out, nil
}

// signingKeys reports the issuer's signing-key metadata (candidate, active, and retired). The
// signing key is global/issuer-level, not per-organization, so this endpoint is not
// organization-scoped; it exposes no key material (see Issuer.KeyInfo).
func (h *Handler) signingKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.Service.SigningKeys(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (h *Handler) shadowAI(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ShadowAICandidates(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) reviewShadowAI(w http.ResponseWriter, r *http.Request) {
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
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, ErrReviewerRequired)
		return
	}
	if err := h.Service.ReviewShadowAIClient(r.Context(), organizationID, id, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clientUpdatedMeta is the oidc.client_updated audit metadata; a change to the
// PKCE exemption is recorded with its new end (nil: cleared).
func clientUpdatedMeta(c *Client, in UpdateClientInput) map[string]any {
	meta := map[string]any{"client_id": c.ClientID, "name": c.Name}
	if in.PKCEExemptUntil.Set {
		meta["pkce_exempt_until"] = c.PKCEExemptUntil
	}
	return meta
}
