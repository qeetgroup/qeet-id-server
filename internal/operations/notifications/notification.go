// Package notification is the in-app notification inbox behind the console's
// header bell. Notifications belong to an account, not a tenant: their owner
// reads them and marks them read in any organisation. Other packages call
// Service.Notify through small interfaces, such as for a locked-account alert.
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

// Service stores and reads in-app notifications.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns a Service over pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Notification is one entry of a user's inbox; ReadAt is nil while unread.
type Notification struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Href        string     `json:"href,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
}

// Notify appends a notification for a user; an empty kind means "info".
// tenantID may be uuid.Nil. Callers should log and drop the error, so a failed
// notification never breaks the action that caused it.
func (s *Service) Notify(ctx context.Context, tenantID, userID uuid.UUID, kind, title, description, href string) error {
	if kind == "" {
		kind = "info"
	}
	// tenant_id is nullable; uuid.Nil is stored as NULL.
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

// List returns up to limit of the user's newest notifications (50 if limit is
// not in 1..100) and the user's unread count.
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
		// A NULL read_at means unread.
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

// MarkAllRead marks all of the user's notifications read.
func (s *Service) MarkAllRead(ctx context.Context, userID uuid.UUID) error {
	return s.q.MarkAllNotificationsRead(ctx, userID)
}

// Handler serves the signed-in user's notification inbox.
type Handler struct {
	Service *Service
}

// Mount registers the notification routes.
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
