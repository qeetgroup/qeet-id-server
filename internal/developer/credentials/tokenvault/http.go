package tokenvault

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the token vault. PublicBaseURL is this API's public origin,
// or "" to build OAuth callback URLs from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
	CookieSecure  bool // the browser-binding cookie's Secure attribute; off only in development
}

// binding ties a connect ceremony to the browser that began it: the callback
// stores a connected account only in that browser, or whoever began one could
// send its link to someone else and keep the account they connect.
func (h *Handler) binding() httpx.BindingCookie {
	return httpx.BindingCookie{Name: "qe_vault", Secure: h.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: connectStateTTL}
}

// Mount registers the token vault routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/organizations/{organizationID}/vault/tokens/providers", h.registerProvider)
	r.Get("/organizations/{organizationID}/vault/tokens/providers", h.listProviders)
	r.Delete("/organizations/{organizationID}/vault/tokens/providers/{provider}", h.deleteProvider)
	r.Get("/vault/tokens", h.listGrants)
	r.Get("/vault/tokens/{provider}/connect", h.beginConnect)
	r.Get("/vault/tokens/{provider}/access-token", h.getAccessToken)
	r.Delete("/vault/tokens/{provider}", h.disconnect)
}

// MountPublic mounts the OAuth2 redirect target (no JWT — the third-party
// provider's redirect carries no auth header; the single-use state param is
// the proof).
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/vault/tokens/callback", h.callback)
}

func (h *Handler) registerProvider(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in RegisterProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.RegisterProvider(r.Context(), organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *Handler) listProviders(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListProviders(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) deleteProvider(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteProvider(r.Context(), organizationID, chi.URLParam(r, "provider")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) beginConnect(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	authorizeURL, state, err := h.Service.BeginConnect(r.Context(), organizationID, userID, chi.URLParam(r, "provider"), httpx.PublicOrigin(r, h.PublicBaseURL))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Add(w, r, state)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": authorizeURL})
}

// callback is the OAuth2 redirect target. It renders a minimal, self-contained
// confirmation page rather than redirecting to a caller-supplied URL, so there
// is no open-redirect surface on the return leg.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		writeCallbackPage(w, false, errCode)
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		writeCallbackPage(w, false, "missing state or code")
		return
	}
	if !h.binding().Holds(r, state) {
		writeCallbackPage(w, false, ErrConnectOtherBrowser.Message)
		return
	}
	h.binding().Remove(w, r, state)
	if err := h.Service.FinishConnect(r.Context(), state, code, httpx.PublicOrigin(r, h.PublicBaseURL)); err != nil {
		msg := "connection failed"
		if e := errs.As(err); e != nil {
			msg = e.Message
			if e.Detail != "" {
				msg = e.Detail
			}
		}
		writeCallbackPage(w, false, msg)
		return
	}
	writeCallbackPage(w, true, "")
}

func writeCallbackPage(w http.ResponseWriter, ok bool, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>Connected. You can close this window.</p></body></html>`))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<!doctype html><html><body><p>Connection failed: ` + htmlEscape(errMsg) + `</p></body></html>`)) // #nosec G705 -- errMsg is HTML-escaped
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), organizationID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// getAccessToken returns a live access token, refreshed if needed, only to the
// person who connected the account, signed in themselves (any other credential
// is refused and recorded) and holding vault:<provider> or vault:read. Each
// read is audited.
func (h *Handler) getAccessToken(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	provider := chi.URLParam(r, "provider")
	// A connected account's raw token goes only to the person who connected
	// it, signed in themselves. An API key, service principal, agent or
	// application token carries a user id it was given, not one it proved, so
	// it is refused, and the attempt is recorded as that credential.
	if !signedInPerson(p) {
		h.recordAccessRefused(r, p, organizationID, provider)
		httpx.WriteError(w, r, ErrPeopleOnly)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !hasVaultScope(p.Scopes, provider) {
		httpx.WriteError(w, r, ErrScopeRequired)
		return
	}
	token, err := h.Service.GetAccessToken(r.Context(), organizationID, userID, provider, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_token": token})
}

// signedInPerson reports whether p is a person's own session: not an API key,
// service principal or agent, and not a token issued to an application.
func signedInPerson(p *httpx.Principal) bool {
	return (p.ActorType == "" || p.ActorType == "user") && p.UserID != nil && p.SessionID != nil && p.ClientID == ""
}

// recordAccessRefused audits a refused token read under the credential that
// tried, never under the user id that credential carries.
func (h *Handler) recordAccessRefused(r *http.Request, p *httpx.Principal, organizationID uuid.UUID, provider string) {
	meta := map[string]any{"credential_id": p.Subject}
	if p.UserID != nil {
		meta["target_user_id"] = p.UserID.String()
	}
	if p.ClientID != "" {
		meta["client_id"] = p.ClientID
	}
	actor := audit.ActorOf(r)
	actor.UserID = nil
	h.Service.recordRefusal(r.Context(), organizationID, provider, actor, meta)
}

func hasVaultScope(scopes []string, provider string) bool {
	for _, s := range scopes {
		if s == "vault:read" || s == "vault:"+provider {
			return true
		}
	}
	return false
}

func (h *Handler) disconnect(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Disconnect(r.Context(), organizationID, userID, chi.URLParam(r, "provider")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
