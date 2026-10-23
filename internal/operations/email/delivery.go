package email

import (
	"net/http"
	"net/mail"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

// DeliveryHandler answers whether an organisation's mail arrived, and lets an
// administrator lift a suppression the organisation's mail caused.
type DeliveryHandler struct {
	Store *delivery.Store
}

// Mount registers, under /tenants/{tenantID}/email: GET messages?to=<address>
// (messages to an address and its suppression), GET suppressions, and
// DELETE suppressions/{id}, which is audited.
func (h *DeliveryHandler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/email/messages", h.messages)
	r.Get("/tenants/{tenantID}/email/suppressions", h.suppressions)
	r.Delete("/tenants/{tenantID}/email/suppressions/{id}", h.clear)
}

func listLimit(r *http.Request) int32 {
	if n, err := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 32); err == nil && n > 0 && n <= 100 {
		return int32(n)
	}
	return 50
}

func (h *DeliveryHandler) messages(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	to, err := mail.ParseAddress(r.URL.Query().Get("to"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("to must be an email address"))
		return
	}
	items, err := h.Store.MessagesTo(r.Context(), tenantID, to.Address, listLimit(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := map[string]any{"items": items, "suppression": nil}
	sup, err := h.Store.Suppressed(r.Context(), to.Address)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if sup != nil {
		// Only the organisation whose mail caused a suppression may clear it, so
		// only it is told which one it is, and why and when. Any other learns
		// only that its mail to the address isn't sent.
		view := map[string]any{"own": false}
		if sup.TenantID != nil && *sup.TenantID == tenantID {
			view = map[string]any{"own": true, "id": sup.ID, "reason": sup.Reason, "detail": sup.Detail, "created_at": sup.CreatedAt}
		}
		out["suppression"] = view
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *DeliveryHandler) suppressions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Store.Suppressions(r.Context(), tenantID, listLimit(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *DeliveryHandler) clear(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	actor := audit.Actor{Type: "user", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		actor.UserID = p.UserID
		if p.ActorType != "" {
			actor.Type = p.ActorType
		}
	}
	tx, err := h.Store.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	sup, err := h.Store.ClearSuppression(r.Context(), tx, tenantID, id, actor.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := audit.Record(r.Context(), tx, actor.Event(tenantID, "email.suppression_cleared", "email_suppression", id,
		map[string]any{"address": sup.AddressHint, "reason": sup.Reason})); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
