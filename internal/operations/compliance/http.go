package compliance

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the compliance evidence, control owner and external audit
// endpoints.
type Handler struct {
	Evidence *EvidenceService
}

// Mount registers the routes.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/organizations/{organizationID}/compliance/{framework}/evidence", h.generateEvidence)
	r.Get("/organizations/{organizationID}/compliance/{framework}/evidence", h.listEvidence)
	r.Get("/organizations/{organizationID}/compliance/evidence/{id}", h.getEvidence)
	r.Get("/organizations/{organizationID}/compliance/controls/owners", h.listOwners)
	r.Put("/organizations/{organizationID}/compliance/controls/{controlID}/owner", h.setOwner)
	r.Delete("/organizations/{organizationID}/compliance/controls/{controlID}/owner", h.removeOwner)
	r.Get("/organizations/{organizationID}/compliance/audits", h.listAudits)
	r.Post("/organizations/{organizationID}/compliance/audits", h.recordAudit)
	r.Delete("/organizations/{organizationID}/compliance/audits/{id}", h.deleteAudit)
}

// validEvidenceFramework returns the {framework} path parameter, or
// ErrFrameworkInvalid if it is not supported.
func validEvidenceFramework(r *http.Request) (string, error) {
	f := chi.URLParam(r, "framework")
	if f != "soc2" && f != "iso27001" {
		return "", ErrFrameworkInvalid
	}
	return f, nil
}

// generateEvidence serves POST /organizations/{organizationID}/compliance/{framework}/evidence:
// it runs the framework's controls and returns the full run.
func (h *Handler) generateEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	framework, err := validEvidenceFramework(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	run, err := h.Evidence.Generate(r.Context(), tid, framework, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, run)
}

// listEvidence serves GET /organizations/{organizationID}/compliance/{framework}/evidence:
// the framework's previous runs, newest first, without controls.
func (h *Handler) listEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	framework, err := validEvidenceFramework(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.ListRuns(r.Context(), tid, framework)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// getEvidence serves GET /organizations/{organizationID}/compliance/evidence/{id}: the full
// run, with a Content-Disposition header so it downloads as a report.
func (h *Handler) getEvidence(w http.ResponseWriter, r *http.Request) {
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
	run, err := h.Evidence.GetRun(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition",
		`attachment; filename="evidence-`+run.Framework+`-`+run.ID.String()+`.json"`)
	httpx.WriteJSON(w, http.StatusOK, run)
}

func (h *Handler) listOwners(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.Owners(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) setOwner(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Evidence.SetOwner(r.Context(), tid, chi.URLParam(r, "controlID"), in.UserID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeOwner(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Evidence.RemoveOwner(r.Context(), tid, chi.URLParam(r, "controlID"), audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAudits(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.Audits(r.Context(), tid, r.URL.Query().Get("framework"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) recordAudit(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ExternalAuditInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.RecordAudit(r.Context(), tid, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handler) deleteAudit(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Evidence.DeleteAudit(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
