package tenant

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID        uuid.UUID      `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	Plan      string         `json:"plan"`
	Region    string         `json:"region"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type CreateInput struct {
	Slug     string         `json:"slug" validate:"required,min=2,max=64"`
	Name     string         `json:"name" validate:"required,min=1,max=200"`
	Plan     string         `json:"plan" validate:"omitempty,oneof=free starter pro enterprise"`
	Region   string         `json:"region" validate:"omitempty,max=64"`
	Metadata map[string]any `json:"metadata"`
}

type UpdateInput struct {
	Name     *string        `json:"name,omitempty" validate:"omitempty,min=1,max=200"`
	Status   *string        `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	Plan     *string        `json:"plan,omitempty" validate:"omitempty,oneof=free starter pro enterprise"`
	Region   *string        `json:"region,omitempty" validate:"omitempty,max=64"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
