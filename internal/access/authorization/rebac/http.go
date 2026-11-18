package rebac

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the relationship-tuple routes. Decider answers the
// relationship check across every engine: an attribute (ABAC) deny refuses,
// and a role grant counts without a tuple.
type Handler struct {
	Service *Service
	Decider *decide.Decider
	// Decisions keeps the decisions the check answers (nil: none).
	Decisions *decisionlog.Log
}

// Mount registers the relationship routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/relation-tuples", h.list)
	r.Post("/organizations/{organizationID}/relation-tuples", h.write)
	r.Delete("/organizations/{organizationID}/relation-tuples/{id}", h.del)
	r.Post("/organizations/{organizationID}/relation-tuples/check", h.check)
	r.Get("/organizations/{organizationID}/relation-tuples/graph", h.graph)
	r.Get("/organizations/{organizationID}/relation-tuples/types", h.objectTypes)
	r.Get("/organizations/{organizationID}/relation-tuples/objects", h.objects)
}

func (h *Handler) objectTypes(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ObjectTypes(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) objects(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	out, err := h.Service.Objects(r.Context(), organizationID, q.Get("type"), paging.Limit(q, 100, 500), q.Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	subject := q.Get("subject")
	switch {
	case object != "" && subject != "":
		httpx.WriteError(w, r, ErrObjectSubjectExclusive)
	case object != "":
		out, err := h.Service.List(r.Context(), organizationID, object)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(out))
	case subject != "":
		out, err := h.Service.ListBySubject(r.Context(), organizationID, subject)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, paging.List(out))
	default:
		httpx.WriteError(w, r, ErrObjectOrSubjectRequired)
	}
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		Subject  string `json:"subject"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, err := h.Service.Write(r.Context(), organizationID, in.Object, in.Relation, in.Subject, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
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

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		UserID   string `json:"user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.UserID == "" || in.Relation == "" {
		httpx.WriteError(w, r, ErrUserIDRelationRequired)
		return
	}
	if _, ok := parseObject(in.Object); !ok {
		httpx.WriteError(w, r, errs.ErrReBACObjectInvalid)
		return
	}
	// The check and its explanation share one budget.
	r = r.WithContext(WithRequestBudget(r.Context()))
	dec, err := h.Decider.Relation(r.Context(), organizationID, in.UserID, in.Object, in.Relation)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Decisions.Record(r.Context(), decisionlog.Entry{OrganizationID: organizationID, Source: decisionlog.SourceRelationCheck, Subject: in.UserID,
		Resource: in.Object, Action: in.Relation, Allowed: dec.Allow, Model: dec.Model, Rule: dec.Rule, ReasonCode: dec.ReasonCode})
	dec = h.Decider.ForViewer(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, dec)
	out := map[string]any{"allowed": dec.Allow, "decided_by": dec.DecidedBy()}
	if r.URL.Query().Get("explain") == "true" {
		exp, err := h.Service.CheckExplain(r.Context(), organizationID, in.Object, in.Relation, in.UserID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if len(exp.Path) > 0 {
			out["path"] = exp.Path
		}
		out["trace"] = dec.Trace
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// graph answers GET /v1/organizations/{organizationID}/relation-tuples/graph with Expand's
// graph for ?object=<type:id>&relation=<rel>[&depth=<n>]: who or what can reach
// the resource, and through which relationships.
func (h *Handler) graph(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	object := q.Get("object")
	relation := q.Get("relation")
	if object == "" || relation == "" {
		httpx.WriteError(w, r, ErrObjectRelationRequired)
		return
	}
	depth := maxExpandDepth
	if d := q.Get("depth"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			depth = n
		}
	}
	g, err := h.Service.Expand(r.Context(), organizationID, object, relation, depth)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}
