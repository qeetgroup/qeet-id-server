// Package ratelimits exposes per-organization rate limit overrides over HTTP.
// The actual enforcement is done by platform/cache/ratelimit.OrganizationLimiter;
// this package only owns the CRUD surface (GET/PUT) and delegates mutations
// to the limiter so DB and in-memory cache stay in sync.
package ratelimits

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Limiter is the subset of ratelimit.OrganizationLimiter used by this package.
type Limiter interface {
	ApplyOverride(organizationID uuid.UUID, rate float64, capacity int)
	ClearOverride(organizationID uuid.UUID)
	GetAll(ctx context.Context, pool *pgxpool.Pool) ([]ratelimit.OrganizationLimit, error)
}

// Defaults are the platform-level fallback values shown in the UI when no
// organization override exists.
type Defaults struct {
	OrganizationRate     float64
	OrganizationCapacity int
	UserRate             float64
	UserCapacity         int
	APIKeyRate           float64
	APIKeyCapacity       int
}

// Bucket is a token bucket: Rate requests a second, bursts of Capacity.
type Bucket struct {
	Rate     float64 `json:"rate"`
	Capacity int     `json:"capacity"`
}

// BuiltInLimit is one of the platform's fixed limits, the same for every
// organization: Per says whose requests share a bucket (ip, user or address).
type BuiltInLimit struct {
	Name    string `json:"name"`
	Per     string `json:"per"`
	Applies string `json:"applies"`
	Bucket
}

// LimitConfig is a bucket's rate (requests a second) and capacity (burst).
type LimitConfig struct {
	Rate     *float64 `json:"rate"`
	Capacity *int     `json:"capacity"`
}

// MinRate is the lowest override rate, one request every 100 seconds; a bucket
// that refills slower would outlive any store's expiry.
const MinRate = 0.01

// check refuses an override outside [MinRate, rate] requests a second or
// [1, capacity] burst: an organization may tighten its limits, never lift them
// above the platform's, which protect every organization sharing it.
func (c LimitConfig) check(key string, rate float64, capacity int) error {
	if c.Rate == nil || c.Capacity == nil {
		return nil
	}
	if *c.Rate < MinRate || *c.Rate > rate || *c.Capacity < 1 || *c.Capacity > capacity {
		return errs.ErrUnprocessable.WithDetail(fmt.Sprintf(
			"%s: rate must be between %g and %g, capacity between 1 and %d", key, MinRate, rate, capacity))
	}
	return nil
}

// OrganizationLimits is an organization's limits per organization, user and API key.
type OrganizationLimits struct {
	Organization LimitConfig `json:"organization"`
	User         LimitConfig `json:"user"`
	APIKey       LimitConfig `json:"api_key"`
}

// limitsView is an organization's effective limits with what bounds them: the
// platform defaults, which are also the ceiling an override may reach, the
// lowest rate an override may set, and the built-in limits.
type limitsView struct {
	OrganizationLimits
	Defaults bucketsView    `json:"defaults"`
	Ceiling  bucketsView    `json:"ceiling"`
	MinRate  float64        `json:"min_rate"`
	BuiltIn  []BuiltInLimit `json:"built_in"`
}

// limitsInput is a PUT body: the overrides, and the read-only bounds a body
// read back from GET carries, which are ignored.
type limitsInput struct {
	OrganizationLimits
	Defaults json.RawMessage `json:"defaults"`
	Ceiling  json.RawMessage `json:"ceiling"`
	MinRate  json.RawMessage `json:"min_rate"`
	BuiltIn  json.RawMessage `json:"built_in"`
}

// bucketsView is a value per organization, person and API-key bucket.
type bucketsView struct {
	Organization Bucket `json:"organization"`
	User         Bucket `json:"user"`
	APIKey       Bucket `json:"api_key"`
}
