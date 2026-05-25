// Package passkey holds the data model for WebAuthn passkeys. The
// register/authenticate ceremony requires a real WebAuthn library
// (go-webauthn) and is intentionally stubbed here — the endpoints return
// 501 until that library is integrated. The credential storage layer is
// real so callers can list/delete keys today.
package passkey

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Credential struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       *string    `json:"name"`
	Transports []string   `json:"transports"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, transports, last_used_at, created_at
		FROM auth.passkey_credentials WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.Transports, &c.LastUsedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM auth.passkey_credentials WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/passkeys", h.list)
	r.Delete("/passkeys/{id}", h.delete)
	r.Post("/passkeys/register/begin", notImplemented)
	r.Post("/passkeys/register/finish", notImplemented)
	r.Post("/passkeys/login/begin", notImplemented)
	r.Post("/passkeys/login/finish", notImplemented)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.List(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, &errs.Error{
		Code:    "not_implemented",
		Status:  http.StatusNotImplemented,
		Message: "WebAuthn ceremony pending go-webauthn integration",
	})
}
