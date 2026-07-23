// Package authzen implements the OpenID AuthZEN standard's core Policy Decision
// Point API — POST /access/v1/evaluation — as a thin facade over Qeet ID's
// existing RBAC and ReBAC engines. It makes no authorization decisions of its
// own: every request is translated and forwarded to rbac.Repository or
// rebac.Service, the same engines the native /check endpoints already use.
//
// Routing between the two engines is by resource.type: "permission" routes
// to RBAC (action.name is the permission key, resource.id is ignored — RBAC
// has no resource dimension); anything else routes to ReBAC (resource
// becomes "type:id", action.name becomes the relation).
package authzen

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Subject/Resource/Action are the AuthZEN core request entities.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Action struct {
	Name string `json:"name"`
}

// EvaluationRequest is the AuthZEN §5 evaluation request. Context is
// accepted but only one key is currently interpreted: {"explain": true}
// requests the grant-path trace (RBAC/ReBAC's own ?explain=true) inline in
// the response's context.
type EvaluationRequest struct {
	Subject  Subject        `json:"subject"`
	Resource Resource       `json:"resource"`
	Action   Action         `json:"action"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationResponse is the AuthZEN §5 evaluation response.
type EvaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// rbacChecker/rebacChecker are the slices of rbac.Repository / rebac.Service
// this package needs — interfaces so authzen doesn't need every method both
// packages expose, and so it's mockable in tests without a database.
type rbacChecker interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
	Explain(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (*rbac.Explanation, error)
}

type rebacChecker interface {
	Check(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (bool, error)
	CheckExplain(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (*rebac.Explanation, error)
}

type Service struct {
	rbac  rbacChecker
	rebac rebacChecker
}

func NewService(rbacRepo rbacChecker, rebacSvc rebacChecker) *Service {
	return &Service{rbac: rbacRepo, rebac: rebacSvc}
}

// permissionResourceType is the resource.type sentinel that routes an
// evaluation to RBAC instead of ReBAC (see package doc).
const permissionResourceType = "permission"

// Evaluate translates and forwards one AuthZEN evaluation request to
// whichever engine resource.type selects.
func (s *Service) Evaluate(ctx context.Context, tenantID uuid.UUID, req EvaluationRequest) (*EvaluationResponse, error) {
	if req.Subject.ID == "" {
		return nil, errs.ErrUnprocessable.WithDetail("subject.id is required")
	}
	if req.Action.Name == "" {
		return nil, errs.ErrUnprocessable.WithDetail("action.name is required")
	}
	explain, _ := req.Context["explain"].(bool)

	if req.Resource.Type == permissionResourceType {
		userID, err := uuid.Parse(req.Subject.ID)
		if err != nil {
			return nil, errs.ErrUnprocessable.WithDetail("subject.id must be a UUID")
		}
		if explain {
			exp, err := s.rbac.Explain(ctx, userID, tenantID, req.Action.Name)
			if err != nil {
				return nil, err
			}
			return &EvaluationResponse{Decision: exp.Allowed, Context: map[string]any{"paths": exp.Paths}}, nil
		}
		allowed, err := s.rbac.Check(ctx, userID, tenantID, req.Action.Name)
		if err != nil {
			return nil, err
		}
		return &EvaluationResponse{Decision: allowed}, nil
	}

	if req.Resource.Type == "" || req.Resource.ID == "" {
		return nil, errs.ErrUnprocessable.WithDetail("resource.type and resource.id are required (use resource.type=\"permission\" with resource.id omitted for an RBAC check)")
	}
	object := req.Resource.Type + ":" + req.Resource.ID
	if explain {
		exp, err := s.rebac.CheckExplain(ctx, tenantID, object, req.Action.Name, req.Subject.ID)
		if err != nil {
			return nil, err
		}
		return &EvaluationResponse{Decision: exp.Allowed, Context: map[string]any{"path": exp.Path}}, nil
	}
	allowed, err := s.rebac.Check(ctx, tenantID, object, req.Action.Name, req.Subject.ID)
	if err != nil {
		return nil, err
	}
	return &EvaluationResponse{Decision: allowed}, nil
}

// --- HTTP ---

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/tenants/{tenantID}/access/v1/evaluation", h.evaluate)
}

func (h *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if tenantID != scope {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return
	}
	var in EvaluationRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Evaluate(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
