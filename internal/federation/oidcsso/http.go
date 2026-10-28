package oidcsso

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the connection administration routes and the browser-facing
// sign-in. PublicBaseURL is this API's public origin, or "" to build the
// redirect URI from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
	CookieSecure  bool // the browser-binding cookie's Secure attribute; off only in development
}

// Mount registers the administration routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/oidc-connections", h.list)
	r.Post("/tenants/{tenantID}/oidc-connections", h.create)
	r.Get("/tenants/{tenantID}/oidc-connections/{id}", h.get)
	r.Patch("/tenants/{tenantID}/oidc-connections/{id}", h.update)
	r.Delete("/tenants/{tenantID}/oidc-connections/{id}", h.del)
}

// MountPublic registers the sign-in routes, which carry no user token.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/oidc-connections/{id}/login", h.login)
	r.Get("/oidc-connections/{id}/callback", h.callback)
	r.Post("/oidc-connections/exchange", h.exchange)
}

// binding ties a sign-in to the browser that began it, so the callback
// completes it only there. The provider returns with a top-level GET, which
// carries a SameSite=Lax cookie.
func (h *Handler) binding() httpx.BindingCookie {
	return httpx.BindingCookie{Name: "qe_oidc_sso", Secure: h.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: stateTTL}
}

// redirectURI is where connection id's provider sends the browser back; the
// organisation registers it with its provider.
func (h *Handler) redirectURI(r *http.Request, id uuid.UUID) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL) + "/v1/oidc-connections/" + id.String() + "/callback"
}

// withRedirectURI fills in c's redirect URI for the response.
func (h *Handler) withRedirectURI(r *http.Request, c *Connection) *Connection {
	c.RedirectURI = h.redirectURI(r, c.ID)
	return c
}

func connectionID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errs.ErrOIDCSSOIDInvalid
	}
	return id, nil
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := tenantID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "oidc_connection",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	})
}

// --- administration ---

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for i := range out {
		h.withRedirectURI(r, &out[i])
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := in.check(h.Service.egress); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.Service.RequireSSO(ctx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Create(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	meta := map[string]any{"name": conn.Name, "issuer": conn.Issuer, "status": conn.Status}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "oidc_connection.created", meta); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, h.withRedirectURI(r, conn))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := connectionID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Get(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withRedirectURI(r, conn))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := connectionID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
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
	conn, err := h.Service.Update(ctx, tx, id, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	meta := map[string]any{"fields": in.changed(), "status": conn.Status}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "oidc_connection.updated", meta); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withRedirectURI(r, conn))
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := connectionID(r)
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
	if err := h.Service.Delete(ctx, tx, id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, id, "oidc_connection.deleted", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- sign-in ---
//
// Browser-facing: success is a redirect; errors use the standard JSON error
// envelope, as the SAML sign-in's do.

// login sends the browser to the connection's provider and gives it the
// binding the callback checks.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	id, err := connectionID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	authURL, state, err := h.Service.BeginSignIn(r.Context(), id, h.redirectURI(r, id))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Add(w, r, state)
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- authorization_endpoint checked by validAuthorizationEndpoint
}

// callback completes a sign-in the provider answered, then hands the console
// a one-time code in the URL fragment, which is never sent to a server; the
// console trades it at POST /v1/oidc-connections/exchange.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	id, err := connectionID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	state := query.Get("state")
	startedHere := h.binding().Holds(r, state)
	code, err := h.Service.CompleteSignIn(r.Context(), Callback{
		ConnectionID:  id,
		State:         state,
		Code:          query.Get("code"),
		ProviderError: query.Get("error"),
		StartedHere:   startedHere,
		IP:            httpx.ClientIP(r),
		UserAgent:     r.UserAgent(),
	})
	if startedHere {
		h.binding().Remove(w, r, state)
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, h.Service.appBaseURL+"/sso/callback#oidc_code="+code, http.StatusFound)
}

func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.ExchangeLogin(r.Context(), body.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
