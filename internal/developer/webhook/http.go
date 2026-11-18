package webhook

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the webhook HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the webhook routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/webhooks", h.create)
	r.Get("/organizations/{organizationID}/webhooks", h.list)
	r.Get("/organizations/{organizationID}/webhooks/events", h.events)
	r.Post("/organizations/{organizationID}/webhooks/{id}/enable", h.enable)
	r.Post("/organizations/{organizationID}/webhooks/{id}/rotate-secret", h.rotateSecret)
	r.Patch("/organizations/{organizationID}/webhooks/{id}", h.update)
	r.Post("/organizations/{organizationID}/webhooks/{id}/deliveries/retry", h.retryDead)
	r.Get("/organizations/{organizationID}/webhooks/{id}/deliveries/{deliveryID}/attempts", h.attempts)
	r.Get("/webhooks/{id}", h.get)
	r.Delete("/webhooks/{id}", h.disable)
	r.Post("/webhooks/{id}/test", h.test)
	r.Get("/webhooks/{id}/deliveries", h.listDeliveries)
	r.Post("/webhooks/{id}/deliveries/{deliveryID}/retry", h.retryDelivery)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) listDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	after, err := paging.ParseCursor(q)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, next, err := h.Service.ListDeliveries(r.Context(), id, organizationID, paging.Limit(q, 50, 200), after, q.Get("status"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(out, next))
}

func (h *Handler) retryDelivery(w http.ResponseWriter, r *http.Request) {
	subscriptionID, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	deliveryID, err := httpx.PathUUID(r, "deliveryID", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RetryDelivery(r.Context(), subscriptionID, deliveryID, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Delivery re-queued."})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = organizationID // scope from principal, never the body
	sub, err := h.Service.Create(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sub)
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

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Disable(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Get(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.SendTest(r.Context(), sub); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true, "subscription": sub.ID})
}

// pathSubscription returns the {organizationID} and {id} of an organization-path webhook
// route.
func pathSubscription(r *http.Request) (organizationID, id uuid.UUID, err error) {
	if organizationID, err = httpx.PathOrganization(r); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if id, err = httpx.PathUUID(r, "id", ErrInvalidID); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return organizationID, id, nil
}

// enable turns a disabled subscription back on.
func (h *Handler) enable(w http.ResponseWriter, r *http.Request) {
	organizationID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Enable(r.Context(), id, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

// rotateSecret replaces a subscription's signing secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	organizationID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	secret, until, err := h.Service.RotateSecret(r.Context(), id, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secret": secret, "previous_secret_expires_at": until})
}

// events lists the event catalogue.
func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(Events))
}

// update handles PATCH /v1/organizations/{organizationID}/webhooks/{id}: a new URL, new
// events, or both, audited with what changed.
func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	after, err := h.Service.Update(r.Context(), id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, after)
}

// retryDead handles POST /v1/organizations/{organizationID}/webhooks/{id}/deliveries/retry:
// the subscription's given-up deliveries are sent again.
func (h *Handler) retryDead(w http.ResponseWriter, r *http.Request) {
	organizationID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.RetryDead(r.Context(), id, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"requeued": n})
}

// attempts handles GET /v1/organizations/{organizationID}/webhooks/{id}/deliveries/
// {deliveryID}/attempts: every try at one delivery.
func (h *Handler) attempts(w http.ResponseWriter, r *http.Request) {
	organizationID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	deliveryID, err := httpx.PathUUID(r, "deliveryID", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Attempts(r.Context(), id, deliveryID, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}
