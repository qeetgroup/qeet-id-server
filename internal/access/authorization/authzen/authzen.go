// Package authzen implements the OpenID AuthZEN evaluation API
// (POST .../access/v1/evaluation) over the composed decision (decide.Decider).
// resource.type "permission" asks whether the subject holds the permission
// action.name; any other type asks about relation action.name on "type:id".
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

// Subject is the AuthZEN subject of an evaluation request.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Resource is the AuthZEN resource of an evaluation request.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Action is the AuthZEN action of an evaluation request.
type Action struct {
	Name string `json:"name"`
}

// EvaluationRequest is the AuthZEN §5 evaluation request. Of Context only
// {"explain": true} is read: it adds the grant path and the decision's trace
// to the response's context.
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

// rbacChecker is the slice of rbac.Repository this package needs, and
// rebacChecker the slice of rebac.Service, so tests need no database.
type rbacChecker interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
	Explain(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (*rbac.Explanation, error)
}

type rebacChecker interface {
	Check(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (bool, error)
	CheckExplain(ctx context.Context, tenantID uuid.UUID, object, relation, userID string) (*rebac.Explanation, error)
}

// Service answers AuthZEN evaluation requests from the tenant's roles and
// relationships.
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

// permissionResourceType is the resource.type that asks a permission question
// rather than a relationship one (see package doc).
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

// Handler serves the AuthZEN evaluation HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the AuthZEN evaluation routes on r.
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
