package ldap

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the LDAP HTTP API.
type Handler struct {
	Service *Service
	// CookieSecure marks the hosted login session cookie Secure; off only in development.
	CookieSecure bool
	// ActOnCheck lets a change of what a connection trusts through only for a
	// caller who outranks every administrator linked to it (rbac CheckActOn).
	// Without it the change is refused while one is linked.
	ActOnCheck identitylink.ActOn
}

// Mount registers the LDAP routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/ldap", h.list)
	r.Post("/organizations/{organizationID}/ldap", h.create)
	r.Get("/organizations/{organizationID}/ldap/{id}", h.get)
	r.Patch("/organizations/{organizationID}/ldap/{id}", h.update)
	r.Delete("/organizations/{organizationID}/ldap/{id}", h.del)
	r.Post("/organizations/{organizationID}/ldap/{id}/test", h.test)
}

// MountPublic registers the LDAP routes that take no user token.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/ldap/{id}/authenticate", h.authenticateHTTP)
	r.Post("/ldap/{id}/session", h.sessionHTTP)
}

// sessionHTTP signs a person in to the hosted login with their directory user name and password,
// as POST /v1/auth/session does with a password: the session cookie, or the challenge to complete
// first at POST /v1/auth/session/mfa.
func (h *Handler) sessionHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.LoginSession(r.Context(), id, body.Username, body.Password, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	auth.SetLoginSessionCookie(w, res.RawCookie, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": res.UserID})
}

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
	in.Name = strings.TrimSpace(in.Name)
	in.ServerURL = strings.TrimSpace(in.ServerURL)
	if in.Name == "" || in.ServerURL == "" || strings.TrimSpace(in.BindDN) == "" ||
		in.BindPassword == "" || strings.TrimSpace(in.BaseDN) == "" {
		httpx.WriteError(w, r, ErrConnectionFieldsRequired)
		return
	}
	if !strings.HasPrefix(strings.ToLower(in.ServerURL), "ldap://") && !strings.HasPrefix(strings.ToLower(in.ServerURL), "ldaps://") {
		httpx.WriteError(w, r, ErrServerURLInvalid)
		return
	}
	conn, err := h.Service.Create(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conn)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, ErrStatusInvalid)
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
	conn, err := h.Service.Update(ctx, id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.TestConnection(r.Context(), organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) authenticateHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Login(r.Context(), id, body.Username, body.Password, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		// The directory accepted the password; the client completes the
		// challenge at POST /v1/auth/mfa.
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}
