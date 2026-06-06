package verification

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
)

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/users/{id}/verify/email/start", h.startEmail)
	r.Post("/users/{id}/verify/email/confirm", h.confirmEmail)
	r.Post("/users/{id}/verify/phone/start", h.startPhone)
	r.Post("/users/{id}/verify/phone/confirm", h.confirmPhone)
}

type startEmailInput struct {
	Email string `json:"email"`
}

func (h *Handler) startEmail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in startEmailInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.StartEmail(r.Context(), id, in.Email); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

type confirmInput struct {
	Code string `json:"code"`
}

func (h *Handler) confirmEmail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in confirmInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ConfirmEmail(r.Context(), id, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type startPhoneInput struct {
	Phone string `json:"phone"`
}

func (h *Handler) startPhone(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in startPhoneInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.StartPhone(r.Context(), id, in.Phone); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) confirmPhone(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in confirmInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ConfirmPhone(r.Context(), id, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
