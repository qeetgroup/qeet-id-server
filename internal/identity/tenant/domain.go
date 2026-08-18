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
	LogoURL   string         `json:"logo_url"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// List-only enrichment (populated by List; nil on single-tenant fetches):
	// per-org member counts for the Organizations admin table.
	MemberCount     *int64 `json:"member_count,omitempty"`
	MFAEnabledCount *int64 `json:"mfa_enabled_count,omitempty"`
}

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

type UpdateInput struct {
	Name   *string `json:"name,omitempty" validate:"omitempty,min=1,max=200"`
	Status *string `json:"status,omitempty" validate:"omitempty,oneof=active suspended"`
	// Plan is intentionally NOT updatable here. It changes only through billing
	// (checkout / subscription change), which keeps tenants.plan in sync with what
	// the tenant actually pays for — otherwise an admin could PATCH themselves onto
	// a paid tier for free. See operations/billing ChangePlan → SetTenantPlan.
	Region   *string        `json:"region,omitempty" validate:"omitempty,max=64"`
	LogoURL  *string        `json:"logo_url,omitempty" validate:"omitempty,max=3000000"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
