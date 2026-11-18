package saml

import (
	"net/http"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

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
	items := make([]connectionView, len(out))
	for i := range out {
		items[i] = h.view(r, &out[i])
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

// connectionView is a connection with the addresses its IdP is given.
type connectionView struct {
	*Connection
	SPAddresses
}

// view is conn with its addresses on the API's public origin.
func (h *Handler) view(r *http.Request, conn *Connection) connectionView {
	return connectionView{Connection: conn, SPAddresses: Addresses(h.publicBase(r), conn.ID)}
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
	in.IdpEntityID = strings.TrimSpace(in.IdpEntityID)
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	// A name alone makes a draft, whose addresses go to the IdP before its
	// details come back; any detail given brings the rest with it.
	if in.Name == "" || (!in.awaitsIdP() && (in.IdpEntityID == "" || in.IdpSSOURL == "" || strings.TrimSpace(in.IdpCertificate) == "")) {
		httpx.WriteError(w, r, ErrConnectionFieldsRequired)
		return
	}
	if err := in.check(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.Service.RequireSSO(ctx, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Create(ctx, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, h.view(r, conn))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(r, conn))
}

// test runs a config preflight over a SAML connection and returns per-check
// results so the admin can fix issues before enabling it.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.TestConnection(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
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
	if err := in.check(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if in.IdpEntityID != nil || in.IdpCertificate != nil {
		current, err := h.Service.Get(ctx, id, organizationID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if in.ChangesTrust(current) {
			if err := h.checkTrust(r, organizationID, id); err != nil {
				httpx.WriteError(w, r, err)
				return
			}
		}
	}
	conn, err := h.Service.Update(ctx, id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(r, conn))
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
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
