package webhook

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// update handles PATCH /v1/tenants/{tenantID}/webhooks/{id}: a new URL, new
// events, or both, audited with what changed.
func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	before, after, err := h.Service.Update(ctx, tx, id, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	changes := map[string]any{}
	if before.URL != after.URL {
		changes["url"] = map[string]any{"from": before.URL, "to": after.URL}
	}
	if !slices.Equal(before.Events, after.Events) {
		changes["events"] = map[string]any{"from": before.Events, "to": after.Events}
	}
	if err := h.audit(r, tx, tenantID, id, "webhook.subscription_updated", map[string]any{"changes": changes}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, after)
}

// retryDead handles POST /v1/tenants/{tenantID}/webhooks/{id}/deliveries/retry:
// the subscription's given-up deliveries are sent again.
func (h *Handler) retryDead(w http.ResponseWriter, r *http.Request) {
	tenantID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	n, err := h.Service.RetryDead(ctx, id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.audit(r, tx, tenantID, id, "webhook.deliveries_retried", map[string]any{"requeued": n}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"requeued": n})
}

// attempts handles GET /v1/tenants/{tenantID}/webhooks/{id}/deliveries/
// {deliveryID}/attempts: every try at one delivery.
func (h *Handler) attempts(w http.ResponseWriter, r *http.Request) {
	tenantID, id, err := pathSubscription(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	deliveryID, err := uuid.Parse(chi.URLParam(r, "deliveryID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
		return
	}
	out, err := h.Service.Attempts(r.Context(), id, deliveryID, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}
