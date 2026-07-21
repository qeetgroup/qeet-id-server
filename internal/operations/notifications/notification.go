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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/notifications/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

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
	// tenant_id is nullable in auth.notifications; pass Valid=false for uuid.Nil.
	tid := pgtype.UUID{Bytes: tenantID, Valid: tenantID != uuid.Nil}
	return s.q.InsertNotification(ctx, dbgen.InsertNotificationParams{
		UserID:      userID,
		TenantID:    tid,
		Kind:        kind,
		Title:       title,
		Description: description,
		Href:        href,
	})
}

// List returns a user's most recent notifications plus the unread count.
func (s *Service) List(ctx context.Context, userID uuid.UUID, limit int) ([]Notification, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	genRows, err := s.q.ListNotifications(ctx, dbgen.ListNotificationsParams{
		UserID:   userID,
		RowLimit: int32(limit),
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]Notification, 0, len(genRows))
	for _, r := range genRows {
		n := Notification{
			ID: r.ID, Kind: r.Kind, Title: r.Title,
			Description: r.Description, Href: r.Href, CreatedAt: r.CreatedAt,
		}
		// read_at is nullable timestamptz; pgtype.Timestamptz.Valid signals NULL.
		if r.ReadAt.Valid {
			t := r.ReadAt.Time
			n.ReadAt = &t
		}
		out = append(out, n)
	}
	count, err := s.q.CountUnreadNotifications(ctx, userID)
	if err != nil {
		return nil, 0, err
	}
	return out, int(count), nil
}

// MarkAllRead clears the unread state for all of a user's notifications.
func (s *Service) MarkAllRead(ctx context.Context, userID uuid.UUID) error {
	return s.q.MarkAllNotificationsRead(ctx, userID)
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
