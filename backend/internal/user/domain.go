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
	Status          string         `json:"status"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
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
	DisplayName *string         `json:"display_name,omitempty" validate:"omitempty,max=200"`
	Phone       *string         `json:"phone,omitempty" validate:"omitempty,e164"`
	Status      *string         `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}
