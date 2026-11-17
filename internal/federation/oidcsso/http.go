package oidcsso

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
)

// Handler serves the connection administration routes and the browser-facing
// sign-in. PublicBaseURL is this API's public origin, or "" to build the
// redirect URI from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
	CookieSecure  bool // the browser-binding cookie's Secure attribute; off only in development
	// ActOnCheck lets a change of what a connection trusts through only for a
	// caller who outranks every administrator linked to it (rbac CheckActOn).
	// Without it the change is refused while one is linked.
	ActOnCheck identitylink.ActOn
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
	r.Post("/oidc-connections/session", h.session)
}

// binding ties a sign-in to the browser that began it, so the callback
// completes it only there. The provider returns with a top-level GET, which
// carries a SameSite=Lax cookie.
func (h *Handler) binding() httpx.BindingCookie {
	return httpx.BindingCookie{Name: "qe_oidc_sso", Secure: h.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: stateTTL}
}

// redirectURI is where connection id's provider sends the browser back; the
// organization registers it with its provider.
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

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := organizationID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         action,
		ResourceType:   "oidc_connection",
		ResourceID:     &rid,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       meta,
	})
}

// --- administration ---

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for i := range out {
		h.withRedirectURI(r, &out[i])
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
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
	if err := h.Service.RequireSSO(ctx, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Create(ctx, tx, organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	meta := map[string]any{"name": conn.Name, "issuer": conn.Issuer, "status": conn.Status}
	if err := h.recordAudit(ctx, tx, r, organizationID, conn.ID, "oidc_connection.created", meta); err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := connectionID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withRedirectURI(r, conn))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
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
	// A connection signs its linked accounts in on what it trusts, so changing
	// that acts on each of them.
	current, err := h.Service.Get(ctx, id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.ChangesTrust(current) {
		if err := identitylink.CheckTrustChange(ctx, h.Service.Pool(), httpx.PrincipalFromCtx(ctx), h.ActOnCheck, organizationID, id, ""); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Update(ctx, tx, id, organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	meta := map[string]any{"fields": in.changed(), "status": conn.Status}
	if err := h.recordAudit(ctx, tx, r, organizationID, conn.ID, "oidc_connection.updated", meta); err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
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
	if err := h.Service.Delete(ctx, tx, id, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, organizationID, id, "oidc_connection.deleted", nil); err != nil {
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
	authURL, state, err := h.Service.BeginSignIn(r.Context(), id, h.redirectURI(r, id), r.URL.Query().Get("return_to"))
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
	code, returnTo, err := h.Service.CompleteSignIn(r.Context(), Callback{
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
	if err != nil && returnTo != "" && h.Service.loginBaseURL != "" {
		// Recorded for the organization; the hosted login says only that it didn't work.
		http.Redirect(w, r, returnto.Failed(h.Service.loginBaseURL, returnTo, err), http.StatusFound)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// A sign-in the hosted login started goes back to its sign-in page, which trades the code at
	// /v1/oidc-connections/session and continues to return_to.
	if returnTo != "" && h.Service.loginBaseURL != "" {
		http.Redirect(w, r, h.Service.loginBaseURL+"/sign-in?"+url.Values{"return_to": {returnTo}}.Encode()+"#oidc_code="+code, http.StatusFound)
		return
	}
	http.Redirect(w, r, h.Service.appBaseURL+"/sso/callback#oidc_code="+code, http.StatusFound)
}

// session trades a sign-in the hosted login started for the hosted login session, as
// POST /v1/auth/session answers: the session cookie and the user's id.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, organizationID, err := h.Service.consumeLoginCode(r.Context(), body.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	raw, err := h.Service.auth.BeginSSOLoginSession(r.Context(), userID, organizationID, provider, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID})
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
