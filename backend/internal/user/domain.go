package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	Email           string         `json:"email"`
	EmailVerifiedAt *time.Time     `json:"email_verified_at"`
	Phone           *string        `json:"phone"`
	PhoneVerifiedAt *time.Time     `json:"phone_verified_at"`
	DisplayName     *string        `json:"display_name"`
	AvatarURL       *string        `json:"avatar_url"`
	// Roles holds the user's role names in the listed tenant. Populated only by
	// ListByTenant (the members list); empty on single-user fetches.
	Roles           []string       `json:"roles,omitempty"`
	Status          string         `json:"status"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// DeletedUser is the soft-deleted view shown in the recycle bin — enough to
// identify the record and decide whether to restore or permanently purge it.
type DeletedUser struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	DeletedAt   time.Time `json:"deleted_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateInput struct {
	TenantID    uuid.UUID      `json:"tenant_id" validate:"required"`
	Email       string         `json:"email" validate:"required,email"`
	Password    string         `json:"password" validate:"omitempty,min=8,max=256"`
	DisplayName string         `json:"display_name" validate:"omitempty,max=200"`
	Phone       string         `json:"phone" validate:"omitempty,e164"`
	Metadata    map[string]any `json:"metadata"`
}

type UpdateInput struct {
	DisplayName *string        `json:"display_name,omitempty" validate:"omitempty,max=200"`
	// AvatarURL is a small image data-URL (capped/compressed client-side). Empty
	// string clears it. The startswith guard keeps it to image data-URLs only.
	AvatarURL   *string        `json:"avatar_url,omitempty" validate:"omitempty,max=300000,startswith=data:image/"`
	Phone       *string        `json:"phone,omitempty" validate:"omitempty,e164"`
	Status      *string        `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
