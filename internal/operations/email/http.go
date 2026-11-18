package email

import (
	"context"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Handler serves the email template endpoints.
type Handler struct {
	Service          *Service
	Sender           notifier.Sender
	Appearance       EmailAppearanceSource
	TestEmailEnabled bool
	testLimits       testEmailLimits
}

// Mount registers the email template routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/email-templates", h.list)
	r.Get("/organizations/{organizationID}/email-templates/{key}", h.get)
	r.Put("/organizations/{organizationID}/email-templates/{key}", h.upsert)
	r.Delete("/organizations/{organizationID}/email-templates/{key}", h.reset)
	r.Post("/organizations/{organizationID}/email-templates/{key}/preview", h.preview)
	r.Post("/organizations/{organizationID}/email-templates/{key}/test", h.testEmail)
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
	httpx.WriteJSON(w, http.StatusOK, templateList{
		Result:       paging.Page(out, ""),
		Capabilities: map[string]bool{"rich_text": true, "localization": true, "test_email": h.TestEmailEnabled && h.Sender != nil},
	})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Get(r.Context(), organizationID, chi.URLParam(r, "key"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) upsert(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	key := chi.URLParam(r, "key")
	var in EditorInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.UpsertEditor(r.Context(), organizationID, key, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Reset(r.Context(), organizationID, chi.URLParam(r, "key"), audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) preview(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Vars   map[string]string `json:"vars"`
		Draft  *EditorInput      `json:"draft"`
		Locale string            `json:"locale"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	key := chi.URLParam(r, "key")
	if in.Draft == nil {
		res, err := h.Service.Get(r.Context(), organizationID, key)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		in.Draft = &EditorInput{Subject: res.Subject, Body: res.Body, Options: res.Options}
	}
	result, err := renderEditor(key, *in.Draft, in.Vars, in.Locale, h.appearance(r.Context(), organizationID))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) appearance(ctx context.Context, organizationID uuid.UUID) emailAppearance {
	appearance := emailAppearance{name: "Qeet ID", primary: "#f97316"}
	if h.Appearance == nil {
		return appearance
	}
	name, logo, primary, err := h.Appearance.EmailAppearance(ctx, organizationID)
	if err != nil {
		return appearance
	}
	if strings.TrimSpace(name) != "" {
		appearance.name = name
	}
	if emailColor.MatchString(primary) {
		appearance.primary = primary
	}
	if parsed, err := url.Parse(logo); err == nil && parsed.User == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
		appearance.logo = logo
	}
	return appearance
}

// testEmail sends a rendered draft to the caller's own verified address, once a
// minute at most. It is forbidden unless TestEmailEnabled is set and a Sender
// is configured.
func (h *Handler) testEmail(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	principal := httpx.PrincipalFromCtx(r.Context())
	if principal == nil || principal.UserID == nil || !h.TestEmailEnabled || h.Sender == nil {
		httpx.WriteError(w, r, errs.ErrForbidden)
		return
	}
	var input struct {
		Draft  EditorInput `json:"draft"`
		Locale string      `json:"locale"`
	}
	if err := httpx.DecodeJSON(r, &input); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	recipient, err := h.Service.VerifiedAddress(r.Context(), *principal.UserID)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrForbidden)
		return
	}
	parsed, err := mail.ParseAddress(recipient)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	appearance := h.appearance(r.Context(), organizationID)
	variables := map[string]string{"code": "482913", "ttl": "10 minutes", "organization_name": appearance.name, "reset_url": "https://example.invalid/test/reset", "magic_url": "https://example.invalid/test/sign-in", "invite_url": "https://example.invalid/test/invite"}
	preview, err := renderEditor(chi.URLParam(r, "key"), input.Draft, variables, input.Locale, appearance)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !h.testLimits.allow(organizationID.String()+":"+principal.UserID.String(), time.Now()) {
		w.Header().Set("Retry-After", "60")
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{"code": "rate_limited", "message": "Wait before sending another test email."}})
		return
	}
	if err := h.Service.RecordTestRequested(r.Context(), organizationID, chi.URLParam(r, "key"), audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Sender.Send(r.Context(), notifier.Message{OrganizationID: organizationID.String(), Channel: "email", To: parsed.Address, Subject: "[Test] " + preview.Subject, Body: preview.Body, HTML: preview.HTML}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// DeliveryHandler answers whether an organization's mail arrived, and lets an
// administrator lift a suppression the organization's mail caused.
type DeliveryHandler struct {
	Store *delivery.Store
}

// Mount registers, under /organizations/{organizationID}/email: GET messages?to=<address>
// (messages to an address and its suppression), GET suppressions, and
// DELETE suppressions/{id}, which is audited.
func (h *DeliveryHandler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/email/messages", h.messages)
	r.Get("/organizations/{organizationID}/email/suppressions", h.suppressions)
	r.Delete("/organizations/{organizationID}/email/suppressions/{id}", h.clear)
}

func (h *DeliveryHandler) messages(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	to, err := mail.ParseAddress(r.URL.Query().Get("to"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("to must be an email address"))
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, next, err := h.Store.MessagesTo(r.Context(), organizationID, to.Address, listLimit(r), after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := messagesPage{Result: paging.Page(items, next)}
	sup, err := h.Store.Suppressed(r.Context(), to.Address)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if sup != nil {
		// Only the organization whose mail caused a suppression may clear it, so
		// only it is told which one it is, and why and when. Any other learns
		// only that its mail to the address isn't sent.
		out.Suppression = map[string]any{"own": false}
		if sup.OrganizationID != nil && *sup.OrganizationID == organizationID {
			out.Suppression = map[string]any{"own": true, "id": sup.ID, "reason": sup.Reason, "detail": sup.Detail, "created_at": sup.CreatedAt}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *DeliveryHandler) suppressions(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, next, err := h.Store.Suppressions(r.Context(), organizationID, listLimit(r), after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(items, next))
}

func (h *DeliveryHandler) clear(w http.ResponseWriter, r *http.Request) {
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
	if err := h.clearSuppression(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clearSuppression lifts the organization's suppression id, recorded as actor's in
// the same transaction.
func (h *DeliveryHandler) clearSuppression(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := h.Store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	sup, err := h.Store.ClearSuppression(ctx, tx, organizationID, id, actor.UserID)
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "email.suppression_cleared", "email_suppression", id,
		map[string]any{"address": sup.AddressHint, "reason": sup.Reason})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
