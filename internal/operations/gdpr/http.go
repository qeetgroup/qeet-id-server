package gdpr

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// ReauthChecker re-verifies a user's password before an irreversible action.
// hasPassword is false for an account without a password.
type ReauthChecker interface {
	ReauthPassword(ctx context.Context, userID uuid.UUID, plain string) (hasPassword, ok bool, err error)
}

// Handler serves the GDPR and self-service account endpoints. Reauth, when
// set, makes account deletion require the password of an account that has one.
type Handler struct {
	Service *Service
	Reauth  ReauthChecker
	// ActOnCheck refuses an erasure or export of someone who outranks the
	// caller (rbac.Repository.CheckActOn), as deleting their account is
	// refused. Without it both are refused.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error
}

// Mount registers the routes.
func (h *Handler) Mount(r chi.Router) {
	// Self-service: the signed-in user acts on their own account, and no organization
	// is required.
	r.Post("/account/export", h.exportSelf)
	r.Post("/account/delete", h.deleteSelf)

	r.Post("/gdpr/purge", h.create)
	r.Get("/organizations/{organizationID}/gdpr/purge", h.list)
	r.Delete("/gdpr/purge/{id}", h.cancel)

	r.Post("/gdpr/export", h.createExport)
	r.Get("/organizations/{organizationID}/gdpr/export", h.listExports)
	r.Get("/organizations/{organizationID}/gdpr/export/{id}", h.getExport)
}

// exportSelf returns the current user's portable data as a downloadable JSON
// document.
func (h *Handler) exportSelf(w http.ResponseWriter, r *http.Request) {
	// A person's data spans every organization they belong to.
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	data, err := h.Service.ExportSelf(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-id-account-export.json"`)
	httpx.WriteJSON(w, http.StatusOK, data)
}

// deleteSelfInput is the body of POST /account/delete.
type deleteSelfInput struct {
	Password string `json:"password"`
}

// deleteSelf erases the current user's PII and credentials at once and ends
// their sessions. The client signs the user out afterwards.
func (h *Handler) deleteSelf(w http.ResponseWriter, r *http.Request) {
	// A person's data spans every organization they belong to.
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	// A stolen access token alone must not delete the account: require the
	// password when the account has one. Password-less (social or passkey)
	// accounts pass on the session alone.
	if h.Reauth != nil {
		var in deleteSelfInput
		_ = httpx.DecodeJSON(r, &in)
		hasPassword, ok, err := h.Reauth.ReauthPassword(r.Context(), *p.UserID, in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if hasPassword && !ok {
			// 400, not 401, so the client does not sign the user out over a mistyped
			// password.
			httpx.WriteError(w, r, errs.ErrBadRequest.WithMessage("Incorrect password."))
			return
		}
	}
	if err := h.Service.PurgeSelf(r.Context(), *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkActOn applies ActOnCheck to the caller of r acting on userID in
// organizationID: nobody erases or exports someone who outranks them.
func (h *Handler) checkActOn(r *http.Request, organizationID, userID uuid.UUID) error {
	if h.ActOnCheck == nil {
		return errs.ErrNotImplemented
	}
	return h.ActOnCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, userID)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.checkActOn(r, tid, in.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	req, err := h.Service.Request(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Cancel(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createExport(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ExportInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.checkActOn(r, tid, in.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	req, err := h.Service.RequestExport(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) listExports(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListExports(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// getExport returns an export request; once it is ready, the response carries
// the payload and a Content-Disposition download header.
func (h *Handler) getExport(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.GetExport(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Reading an export is reading the person's data, held to the same rule as
	// asking for it.
	if err := h.checkActOn(r, tid, out.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if out.Status == "ready" {
		w.Header().Set("Content-Disposition", `attachment; filename="export-`+out.ID.String()+`.json"`)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
