// Package organization manages organizations: creating one with its owner,
// listing the organizations a user belongs to, and updating, suspending or
// deleting one.
package organization

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/dbgen"
)

// Organization is an organization as the API returns it.
type Organization struct {
	ID        uuid.UUID      `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	Plan      string         `json:"plan"`
	Region    string         `json:"region"`
	LogoURL   string         `json:"logo_url"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// DeletionDueAt is when a scheduled deletion takes effect; nil: none.
	DeletionDueAt *time.Time `json:"deletion_due_at"`
	// List-only enrichment (populated by List; nil on single-organization fetches):
	// per-org member counts for the Organizations admin table.
	MemberCount     *int64 `json:"member_count,omitempty"`
	MFAEnabledCount *int64 `json:"mfa_enabled_count,omitempty"`
}

// CreateInput is what CreateWithOwner takes.
type CreateInput struct {
	Slug   string `json:"slug" validate:"required,min=2,max=64"`
	Name   string `json:"name" validate:"required,min=1,max=200"`
	Plan   string `json:"plan" validate:"omitempty,oneof=free starter pro enterprise"`
	Region string `json:"region" validate:"omitempty,max=64"`
	// LogoURL is an optional org logo — a hosted URL or a small inline data URL
	// (the console's LogoField emits either). Empty ⇒ the UI shows an initials avatar.
	LogoURL  string         `json:"logo_url" validate:"omitempty,max=3000000"`
	Metadata map[string]any `json:"metadata"`
}

// UpdateInput is a partial organization update. It has no Plan: the plan changes only
// through billing (billing.Service.ChangePlan), so an admin can't move their
// organization onto a paid tier for free.
type UpdateInput struct {
	Name     *string        `json:"name,omitempty" validate:"omitempty,min=1,max=200"`
	Status   *string        `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	Region   *string        `json:"region,omitempty" validate:"omitempty,max=64"`
	LogoURL  *string        `json:"logo_url,omitempty" validate:"omitempty,max=3000000"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Repository reads and writes organizations.
type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	// hostingRegion is the region every organization is created in.
	hostingRegion string
}

// defaultRegion is the hosting region when none is configured.
const defaultRegion = "us-east-1"

// HostingRegion is the region every organization is created in.
func (r *Repository) HostingRegion() string {
	if r.hostingRegion == "" {
		return defaultRegion
	}
	return r.hostingRegion
}

// NewRepository returns a Repository over pool that creates every
// organization in hostingRegion (empty: defaultRegion).
func NewRepository(pool *pgxpool.Pool, hostingRegion string) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool), hostingRegion: hostingRegion}
}
