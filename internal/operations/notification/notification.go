// Package notification is the in-app notification inbox behind the console's
// header bell. Notifications belong to an account, not an organization: their owner
// reads them and marks them read in any organization. Other packages call
// Service.Notify through small interfaces, such as for a locked-account alert.
package notification

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/notification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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

// Notifier puts a line in someone's in-app inbox. Satisfied by *Service; the
// packages that alert people take one.
type Notifier interface {
	Notify(ctx context.Context, organizationID, userID uuid.UUID, kind, title, description, href string) error
}

// Notify appends a notification for a user; an empty kind means "info".
// organizationID may be uuid.Nil. Callers should log and drop the error, so a failed
// notification never breaks the action that caused it.
func (s *Service) Notify(ctx context.Context, organizationID, userID uuid.UUID, kind, title, description, href string) error {
	if kind == "" {
		kind = "info"
	}
	// organization_id is nullable; uuid.Nil is stored as NULL.
	tid := postgres.NullIfZero(organizationID)
	return s.q.InsertNotification(ctx, dbgen.InsertNotificationParams{
		UserID:         userID,
		OrganizationID: tid,
		Kind:           kind,
		Title:          title,
		Description:    description,
		Href:           href,
	})
}

// List returns up to limit of the user's newest notifications (50 when unset,
// at most paging.MaxListItems+1) and the user's unread count.
func (s *Service) List(ctx context.Context, userID uuid.UUID, limit int) ([]Notification, int, error) {
	limit = paging.Clamp(limit, 50, paging.MaxListItems+1)
	genRows, err := s.q.ListNotifications(ctx, dbgen.ListNotificationsParams{
		UserID:   userID,
		RowLimit: int32(limit), // #nosec G115 -- at most paging.MaxListItems+1
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
		n.ReadAt = r.ReadAt
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

// inbox is the user's newest notifications, with how many are unread.
type inbox struct {
	paging.Result[Notification]
	UnreadCount int `json:"unread_count"`
}
