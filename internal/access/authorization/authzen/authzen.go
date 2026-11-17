// Package authzen implements the OpenID AuthZEN evaluation API
// (POST .../access/v1/evaluation, and several at once at .../evaluations)
// over the composed decision (decide.Decider).
// resource.type "permission" asks whether the subject holds the permission
// action.name; any other type asks about relation action.name on "type:id".
package authzen

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Subject is the AuthZEN subject of an evaluation request. Properties are its
// attributes for ABAC policies (subject.*), beside what the platform knows of
// the user, which wins where both name one.
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the AuthZEN resource of an evaluation request. Properties are
// its attributes for ABAC policies (resource.*); type and id win over them.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the AuthZEN action of an evaluation request. Properties are its
// attributes for ABAC policies (action.*); name wins over them.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// EvaluationRequest is the AuthZEN §5 evaluation request. Context is the
// request's context for ABAC policies (context.*), but for "explain": true,
// which adds the grant path and the decision's trace to the response's context.
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

// EvaluationsRequest is the AuthZEN access evaluations request: several
// evaluations, each taking the top-level subject, resource, action or context
// it leaves out. Without evaluations it is a single evaluation request.
type EvaluationsRequest struct {
	Subject     *Subject       `json:"subject,omitempty"`
	Resource    *Resource      `json:"resource,omitempty"`
	Action      *Action        `json:"action,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
	Evaluations []Evaluation   `json:"evaluations,omitempty"`
	Options     struct {
		EvaluationsSemantic string `json:"evaluations_semantic,omitempty"`
	} `json:"options"`
}

// Evaluation is one of an EvaluationsRequest's evaluations; a field left out
// is the request's.
type Evaluation struct {
	Subject  *Subject       `json:"subject,omitempty"`
	Resource *Resource      `json:"resource,omitempty"`
	Action   *Action        `json:"action,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationsResponse is the AuthZEN access evaluations response, a decision
// per evaluation in the request's order.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// Evaluation semantics: run them all, or stop at the first deny or permit.
const (
	executeAll          = "execute_all"
	denyOnFirstDeny     = "deny_on_first_deny"
	permitOnFirstPermit = "permit_on_first_permit"
)

// maxEvaluations is how many evaluations one request may carry.
const maxEvaluations = 100

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
	// Decisions keeps each evaluation's decision (nil: none).
	Decisions *decisionlog.Log
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
	props := decide.Properties{Subject: req.Subject.Properties, Resource: req.Resource.Properties, Action: req.Action.Properties}
	if len(req.Context) > 0 {
		props.Context = make(map[string]any, len(req.Context))
		for k, v := range req.Context {
			if k != "explain" {
				props.Context[k] = v
			}
		}
	}

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
		if dec, err = s.decider.PermissionWith(ctx, tenantID, userID, req.Action.Name, props); err != nil {
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
		if dec, err = s.decider.RelationWith(ctx, tenantID, req.Subject.ID, object, req.Action.Name, props); err != nil {
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

	resource := req.Resource.Type
	if resource != permissionResourceType {
		resource += ":" + req.Resource.ID
	}
	s.Decisions.Record(ctx, decisionlog.Entry{TenantID: tenantID, Source: decisionlog.SourceAuthZEN, Subject: req.Subject.ID,
		Resource: resource, Action: req.Action.Name, Allowed: dec.Allow, Model: dec.Model, Rule: dec.Rule, ReasonCode: dec.ReasonCode})
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

// EvaluateAll answers each of req's evaluations in order, stopping after the
// first deny or permit as its semantic asks. An evaluation the caller got
// wrong is denied with the error in its context, as {status, code, message},
// and counts as a deny; any other error fails the whole request.
func (s *Service) EvaluateAll(ctx context.Context, tenantID uuid.UUID, req EvaluationsRequest) (*EvaluationsResponse, error) {
	semantic := req.Options.EvaluationsSemantic
	switch semantic {
	case "":
		semantic = executeAll
	case executeAll, denyOnFirstDeny, permitOnFirstPermit:
	default:
		return nil, errs.ErrAuthZENSemanticInvalid
	}
	if len(req.Evaluations) > maxEvaluations {
		return nil, errs.ErrAuthZENTooManyEvaluations.WithMetadata(map[string]any{"max": maxEvaluations})
	}
	out := &EvaluationsResponse{Evaluations: make([]EvaluationResponse, 0, len(req.Evaluations))}
	for _, e := range req.Evaluations {
		one := EvaluationRequest{Context: req.Context}
		if s := firstOf(e.Subject, req.Subject); s != nil {
			one.Subject = *s
		}
		if r := firstOf(e.Resource, req.Resource); r != nil {
			one.Resource = *r
		}
		if a := firstOf(e.Action, req.Action); a != nil {
			one.Action = *a
		}
		if e.Context != nil {
			one.Context = e.Context
		}
		res, err := s.Evaluate(ctx, tenantID, one)
		var bad *errs.Error
		if errors.As(err, &bad) && httpx.ErrorStatus(bad) < http.StatusInternalServerError {
			res = &EvaluationResponse{Context: map[string]any{"error": map[string]any{
				"status": httpx.ErrorStatus(bad), "code": bad.Code, "message": bad.Message,
			}}}
		} else if err != nil {
			return nil, err
		}
		out.Evaluations = append(out.Evaluations, *res)
		if (semantic == denyOnFirstDeny && !res.Decision) || (semantic == permitOnFirstPermit && res.Decision) {
			break
		}
	}
	return out, nil
}

// firstOf is item, or top when item is nil.
func firstOf[T any](item, top *T) *T {
	if item != nil {
		return item
	}
	return top
}

// --- HTTP ---

// Handler serves the AuthZEN evaluation HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the AuthZEN evaluation routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/tenants/{tenantID}/access/v1/evaluation", h.evaluate)
	r.Post("/tenants/{tenantID}/access/v1/evaluations", h.evaluations)
}

// tenant is the organisation the request decides in: the path's, which must
// be the caller's.
func tenant(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return uuid.Nil, false
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, false
	}
	if tenantID != scope {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return uuid.Nil, false
	}
	return tenantID, true
}

func (h *Handler) evaluations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant(w, r)
	if !ok {
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
		out, err := h.Service.Evaluate(r.Context(), tenantID, one)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return
	}
	out, err := h.Service.EvaluateAll(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant(w, r)
	if !ok {
		return
	}
	r = r.WithContext(rebac.WithRequestBudget(r.Context()))
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
