package abac

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the ABAC policy HTTP API.
type Handler struct {
	Service *Service
	// Decisions keeps the decisions evaluate answers (nil: none).
	Decisions *decisionlog.Log
}

// Mount registers the ABAC policy routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/abac/policies", h.list)
	r.Post("/organizations/{organizationID}/abac/policies", h.create)
	r.Get("/organizations/{organizationID}/abac/policies/{id}", h.getPolicy)
	r.Patch("/organizations/{organizationID}/abac/policies/{id}", h.update)
	r.Delete("/organizations/{organizationID}/abac/policies/{id}", h.del)
	r.Get("/organizations/{organizationID}/abac/policies/{id}/versions", h.versions)
	r.Post("/organizations/{organizationID}/abac/policies/{id}/versions/{version}/restore", h.restore)
	r.Post("/organizations/{organizationID}/abac/evaluate", h.evalHandler)
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
	p, err := h.Service.Create(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *Handler) getPolicy(w http.ResponseWriter, r *http.Request) {
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
	p, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
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
	p, err := h.Service.Update(r.Context(), id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) versions(w http.ResponseWriter, r *http.Request) {
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
	out, err := h.Service.Versions(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
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
	version, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil || version < 1 {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid version"))
		return
	}
	p, err := h.Service.Restore(r.Context(), id, organizationID, version, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
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

func (h *Handler) evalHandler(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		EvaluationInput
		Draft *Draft `json:"draft"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var decision *Decision
	if in.Draft != nil {
		decision, err = h.Service.EvaluateDraft(r.Context(), organizationID, in.EvaluationInput, *in.Draft)
	} else {
		decision, err = h.Service.Evaluate(r.Context(), organizationID, in.EvaluationInput)
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	source := decisionlog.SourceABACEvaluate
	if in.Draft != nil {
		source = decisionlog.SourceABACDraft
	}
	subject, _ := in.Subject["id"].(string)
	resource := in.Resource.Type
	if in.Resource.ID != "" {
		resource += ":" + in.Resource.ID
	}
	rule, _ := decision.ReasonParams["policy_name"].(string)
	h.Decisions.Record(r.Context(), decisionlog.Entry{OrganizationID: organizationID, Source: source, Subject: subject,
		Resource: resource, Action: in.Action, Allowed: decision.Allow, Model: "abac", Rule: rule, ReasonCode: decision.ReasonCode})
	// Omit the trace unless ?explain=true, mirroring the rebac/authzen convention.
	if r.URL.Query().Get("explain") != "true" {
		decision.Trace = nil
	}
	httpx.WriteJSON(w, http.StatusOK, decision)
}
