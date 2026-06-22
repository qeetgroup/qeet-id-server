// Package notification is the in-app notification inbox shown in the admin
// header bell. Notifications are per-user and append-only; the owner reads them
// and marks them read. Other packages emit via Service.Notify (e.g. a security
// alert when an account is locked), kept behind a small interface so callers
// don't import this package directly.
package notification

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

type Notification struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Href        string     `json:"href,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
}

// Notify appends a notification for a user. Best-effort callers (event hooks)
// should log and swallow the error so a notification write never breaks the
// originating action. tenantID may be uuid.Nil for tenant-less context.
func (s *Service) Notify(ctx context.Context, tenantID, userID uuid.UUID, kind, title, description, href string) error {
	if kind == "" {
		kind = "info"
	}
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.notifications (user_id, tenant_id, kind, title, description, href)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, tid, kind, title, description, href)
	return err
}

// List returns a user's most recent notifications plus the unread count.
func (s *Service) List(ctx context.Context, userID uuid.UUID, limit int) ([]Notification, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, title, description, href, created_at, read_at
		FROM auth.notifications WHERE user_id = $1
		ORDER BY created_at DESC LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]Notification, 0)
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Kind, &n.Title, &n.Description, &n.Href, &n.CreatedAt, &n.ReadAt); err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var unread int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM auth.notifications WHERE user_id = $1 AND read_at IS NULL
	`, userID).Scan(&unread); err != nil {
		return nil, 0, err
	}
	return out, unread, nil
}

// MarkAllRead clears the unread state for all of a user's notifications.
func (s *Service) MarkAllRead(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth.notifications SET read_at = NOW()
		WHERE user_id = $1 AND read_at IS NULL
	`, userID)
	return err
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/notifications", h.list)
	r.Post("/notifications/mark-all-read", h.markAllRead)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	items, unread, err := h.Service.List(r.Context(), *p.UserID, 50)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "unread_count": unread})
}

func (h *Handler) markAllRead(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err := h.Service.MarkAllRead(r.Context(), *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
