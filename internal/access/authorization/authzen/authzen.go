// Package authzen implements the OpenID AuthZEN standard's core Policy Decision
// Point API — POST /access/v1/evaluation — as a thin facade over Qeet ID's
// composed decision (decide.Decider), the same one the native /check endpoints
// use: an attribute (ABAC) deny refuses, then roles, relationships and
// attribute allow policies are a union. It makes no decision of its own.
//
// The question asked is chosen by resource.type: "permission" asks about a
// permission (action.name is the key, resource.id is ignored); anything else
// asks about a relationship (resource becomes "type:id", action.name the
// relation). The response context names the deciding model and rule.
package authzen

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
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
// requests the grant path (RBAC/ReBAC's own ?explain=true) and the decision's
// trace inline in the response's context.
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
	rbac    rbacChecker
	rebac   rebacChecker
	decider *decide.Decider
}

// NewService fronts decider; rbacRepo and rebacSvc supply the grant paths an
// explain request asks for.
func NewService(rbacRepo rbacChecker, rebacSvc rebacChecker, decider *decide.Decider) *Service {
	return &Service{rbac: rbacRepo, rebac: rebacSvc, decider: decider}
}

// permissionResourceType is the resource.type sentinel that routes an
// evaluation to RBAC instead of ReBAC (see package doc).
const permissionResourceType = "permission"

// Evaluate translates one AuthZEN evaluation request into the composed
// decision resource.type selects. The ABAC policy that decided is named only to
// a caller who may read policies (decide.Decider.ForViewer).
func (s *Service) Evaluate(ctx context.Context, tenantID uuid.UUID, req EvaluationRequest) (*EvaluationResponse, error) {
	if req.Subject.ID == "" {
		return nil, errs.ErrAuthZENSubjectIDRequired
	}
	if req.Action.Name == "" {
		return nil, errs.ErrAuthZENActionNameRequired
	}
	explain, _ := req.Context["explain"].(bool)

	var (
		dec  decide.Decision
		err  error
		path map[string]any
	)
	if req.Resource.Type == permissionResourceType {
		userID, perr := uuid.Parse(req.Subject.ID)
		if perr != nil {
			return nil, errs.ErrAuthZENSubjectIDInvalid
		}
		if dec, err = s.decider.Permission(ctx, tenantID, userID, req.Action.Name); err != nil {
			return nil, err
		}
		if explain {
			exp, err := s.rbac.Explain(ctx, userID, tenantID, req.Action.Name)
			if err != nil {
				return nil, err
			}
			path = map[string]any{"paths": exp.Paths}
		}
	} else {
		if req.Resource.Type == "" || req.Resource.ID == "" {
			return nil, errs.ErrAuthZENResourceRequired
		}
		object := req.Resource.Type + ":" + req.Resource.ID
		if dec, err = s.decider.Relation(ctx, tenantID, req.Subject.ID, object, req.Action.Name); err != nil {
			return nil, err
		}
		if explain {
			exp, err := s.rebac.CheckExplain(ctx, tenantID, object, req.Action.Name, req.Subject.ID)
			if err != nil {
				return nil, err
			}
			path = map[string]any{"path": exp.Path}
		}
	}

	dec = s.decider.ForViewer(ctx, httpx.PrincipalFromCtx(ctx), tenantID, dec)
	out := &EvaluationResponse{Decision: dec.Allow, Context: map[string]any{"decided_by": dec.DecidedBy()}}
	if explain {
		for k, v := range path {
			out.Context[k] = v
		}
		out.Context["trace"] = dec.Trace
	}
	return out, nil
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
