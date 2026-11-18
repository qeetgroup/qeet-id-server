package authzen

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the AuthZEN evaluation HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the AuthZEN evaluation routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/organizations/{organizationID}/access/v1/evaluation", h.evaluate)
	r.Post("/organizations/{organizationID}/access/v1/evaluations", h.evaluations)
}

func (h *Handler) evaluations(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The request's relationship checks share one budget, however many it makes.
	r = r.WithContext(rebac.WithRequestBudget(r.Context()))
	var in EvaluationsRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(in.Evaluations) == 0 {
		one := EvaluationRequest{Context: in.Context}
		if in.Subject != nil {
			one.Subject = *in.Subject
		}
		if in.Resource != nil {
			one.Resource = *in.Resource
		}
		if in.Action != nil {
			one.Action = *in.Action
		}
		out, err := h.Service.Evaluate(r.Context(), organizationID, one)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return
	}
	out, err := h.Service.EvaluateAll(r.Context(), organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	r = r.WithContext(rebac.WithRequestBudget(r.Context()))
	var in EvaluationRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Evaluate(r.Context(), organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
