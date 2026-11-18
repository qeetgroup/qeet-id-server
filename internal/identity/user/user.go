// Package user manages user accounts and their membership of organizations: the
// /users admin API and /me, bulk and vendor imports, suspension, and the User
// 360 views.
package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
)

// User is a user account.
type User struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  uuid.UUID  `json:"organization_id"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	Phone           *string    `json:"phone"`
	PhoneVerifiedAt *time.Time `json:"phone_verified_at"`
	DisplayName     *string    `json:"display_name"`
	AvatarURL       *string    `json:"avatar_url"`
	// Roles holds the user's role names in the organization reading them, and
	// AssignedRoles the same roles with their IDs. Set on the members list and
	// a member's own record, not on account-level reads.
	Roles         []string       `json:"roles,omitempty"`
	AssignedRoles []RoleRef      `json:"assigned_roles,omitempty"`
	Status        string         `json:"status"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	// A member's standing in the organization reading them, set where the
	// roles are: a confirmed second factor, its groups they're in, when and
	// from where they were last seen there, the name of the organization that
	// manages their account, and, for its own suspended people, why and by whom.
	MfaEnabled           *bool       `json:"mfa_enabled,omitempty"`
	GroupsCount          *int        `json:"groups_count,omitempty"`
	LastSeenAt           *time.Time  `json:"last_seen_at,omitempty"`
	LastSeenIP           *string     `json:"last_seen_ip,omitempty"`
	HomeOrganizationName *string     `json:"home_organization_name,omitempty"`
	Suspension           *Suspension `json:"suspension,omitempty"`
}

// SeenBy is u as organization organizationID sees it: a person whose home is
// another organization keeps their metadata from it, as that organization
// keeps it about them. It returns u, changed in place.
func (u *User) SeenBy(organizationID uuid.UUID) *User {
	if u.OrganizationID != organizationID {
		u.Metadata = map[string]any{}
	}
	return u
}

// DeletedUser is the soft-deleted view shown in the recycle bin — enough to
// identify the record and decide whether to restore or permanently purge it.
type DeletedUser struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	DeletedAt   time.Time `json:"deleted_at"`
	// DeletedBy is the admin who deleted the user (nil for a deletion that
	// wasn't recorded, or a system one).
	DeletedBy *uuid.UUID `json:"deleted_by"`
	CreatedAt time.Time  `json:"created_at"`
}

// Deletion is what an admin's soft delete removed: the user, when, and by whom.
type Deletion struct {
	ID        uuid.UUID  `json:"id"`
	DeletedAt time.Time  `json:"deleted_at"`
	DeletedBy *uuid.UUID `json:"deleted_by"`
}

// CreateInput is what CreateWithCredential takes: a new user's profile.
type CreateInput struct {
	OrganizationID uuid.UUID      `json:"organization_id" validate:"required"`
	Email          string         `json:"email" validate:"required,email"`
	Password       string         `json:"password" validate:"omitempty,max=256"`
	DisplayName    string         `json:"display_name" validate:"omitempty,max=200"`
	Phone          string         `json:"phone" validate:"omitempty,e164"`
	Metadata       map[string]any `json:"metadata"`
}

// BulkUserInput is one row of a bulk user import (POST /v1/users/bulk). line
// is the row's line in a vendor export file, zero for a row of the JSON array.
type BulkUserInput struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"omitempty,max=256"`
	DisplayName string `json:"display_name" validate:"omitempty,max=200"`
	Phone       string `json:"phone" validate:"omitempty,e164"`
	line        int
}

// BulkCreateInput is the POST /v1/users/bulk request body. OrganizationID is optional;
// when present it must match the caller's organization (enforced in the handler).
type BulkCreateInput struct {
	OrganizationID uuid.UUID       `json:"organization_id"`
	Users          []BulkUserInput `json:"users" validate:"required,min=1,max=1000"`
	// RoleID, when set, is given to every user the import makes.
	RoleID *uuid.UUID `json:"role_id"`
}

// BulkImportError describes why a single row failed. Line is the row's 1-based
// position in the submitted users array, or its line in an export file (for
// azure_b2c, its position in value); zero when the whole file failed. Code is
// one of importErrorCodes, and Field the row's JSON field it concerns, if any.
type BulkImportError struct {
	Line    int    `json:"line,omitempty"`
	Email   string `json:"email,omitempty"`
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// BulkImportResult is the POST /v1/users/bulk response — a per-row summary.
type BulkImportResult struct {
	Succeeded int               `json:"succeeded"`
	Failed    int               `json:"failed"`
	Errors    []BulkImportError `json:"errors,omitempty"`
	Created   []BulkCreatedUser `json:"created"`
}

// BulkCreatedUser is a user a bulk import made, by its row.
type BulkCreatedUser struct {
	Line  int       `json:"line"`
	Email string    `json:"email"`
	ID    uuid.UUID `json:"id"`
}

// UpdateInput is what Update takes.
type UpdateInput struct {
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,max=200"`
	// AvatarURL is a small image data-URL (capped/compressed client-side). Empty
	// string clears it. The startswith guard keeps it to image data-URLs only.
	AvatarURL *string `json:"avatar_url,omitempty" validate:"omitempty,max=300000,len=0|startswith=data:image/"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,e164"`
	Status    *string `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	// Locale is the user's preferred UI language (one of the shipped console
	// locales). Self-service; persisted in metadata by updateMe, not a column.
	Locale   *string        `json:"locale,omitempty" validate:"omitempty,oneof=en de es fr hi ja pt zh"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Repository reads and writes users.
type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewRepository returns a Repository over pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }
