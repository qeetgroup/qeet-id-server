package ratelimits

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the rate-limit override HTTP API.
type Handler struct {
	Pool            *pgxpool.Pool
	OrganizationLim Limiter
	UserLim         Limiter
	APIKeyLim       Limiter
	Defaults        Defaults
	BuiltIn         []BuiltInLimit // reported, read-only
}

// Mount registers the rate-limit override routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/rate-limits", h.get)
	r.Put("/organizations/{organizationID}/rate-limits", h.put)
	r.Delete("/organizations/{organizationID}/rate-limits", h.del)
}

// view adds the bounds to limits.
func (h *Handler) view(limits OrganizationLimits) limitsView {
	d := bucketsView{
		Organization: Bucket{Rate: h.Defaults.OrganizationRate, Capacity: h.Defaults.OrganizationCapacity},
		User:         Bucket{Rate: h.Defaults.UserRate, Capacity: h.Defaults.UserCapacity},
		APIKey:       Bucket{Rate: h.Defaults.APIKeyRate, Capacity: h.Defaults.APIKeyCapacity},
	}
	builtIn := h.BuiltIn
	if builtIn == nil {
		builtIn = []BuiltInLimit{}
	}
	return limitsView{OrganizationLimits: limits, Defaults: d, Ceiling: d, MinRate: MinRate, BuiltIn: builtIn}
}

func (h *Handler) effectiveLimits(ctx context.Context, organizationID uuid.UUID) (OrganizationLimits, error) {
	// Create a lightweight Queries instance bound to the pool. This avoids
	// adding a stored field to Handler (whose struct literal is built in the
	// router composition root without a constructor call).
	q := dbgen.New(h.Pool)
	rows, err := q.GetRateLimitOverrides(ctx, organizationID)
	if err != nil {
		return OrganizationLimits{}, err
	}

	out := OrganizationLimits{
		Organization: LimitConfig{Rate: &h.Defaults.OrganizationRate, Capacity: &h.Defaults.OrganizationCapacity},
		User:         LimitConfig{Rate: &h.Defaults.UserRate, Capacity: &h.Defaults.UserCapacity},
		APIKey:       LimitConfig{Rate: &h.Defaults.APIKeyRate, Capacity: &h.Defaults.APIKeyCapacity},
	}
	for _, row := range rows {
		r, c := row.Rate, int(row.Capacity)
		switch row.LimitKey {
		case "organization":
			out.Organization = LimitConfig{Rate: &r, Capacity: &c}
		case "user":
			out.User = LimitConfig{Rate: &r, Capacity: &c}
		case "api_key":
			out.APIKey = LimitConfig{Rate: &r, Capacity: &c}
		}
	}
	return out, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limits, err := h.effectiveLimits(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(limits))
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body limitsInput
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in := body.OrganizationLimits
	d := h.Defaults
	for _, err := range []error{
		in.Organization.check("organization", d.OrganizationRate, d.OrganizationCapacity),
		in.User.check("user", d.UserRate, d.UserCapacity),
		in.APIKey.check("api_key", d.APIKeyRate, d.APIKeyCapacity),
	} {
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := h.save(r.Context(), organizationID, in, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limits, err := h.effectiveLimits(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(limits))
}

// save stores the overrides in, recorded as actor's, then applies them to the
// limiters once they are committed. A limit given without both rate and
// capacity is left as it is.
func (h *Handler) save(ctx context.Context, organizationID uuid.UUID, in OrganizationLimits, actor audit.Actor) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	type appliedOverride struct {
		limiter  Limiter
		rate     float64
		capacity int
	}
	var applied []appliedOverride
	metadata := map[string]any{}
	for _, item := range []struct {
		key string
		lim Limiter
		cfg LimitConfig
	}{{"organization", h.OrganizationLim, in.Organization}, {"user", h.UserLim, in.User}, {"api_key", h.APIKeyLim, in.APIKey}} {
		if item.cfg.Rate == nil || item.cfg.Capacity == nil {
			continue
		}
		if err := q.UpsertRateLimitOverride(ctx, dbgen.UpsertRateLimitOverrideParams{
			OrganizationID: organizationID,
			LimitKey:       item.key,
			Rate:           *item.cfg.Rate,
			Capacity:       int32(*item.cfg.Capacity), // #nosec G115 -- checked against the platform's capacity
		}); err != nil {
			return err
		}
		applied = append(applied, appliedOverride{limiter: item.lim, rate: *item.cfg.Rate, capacity: *item.cfg.Capacity})
		metadata[item.key] = map[string]any{"rate": *item.cfg.Rate, "capacity": *item.cfg.Capacity}
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "rate_limits.updated", "organization", organizationID, metadata)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: organizationID, Topic: "rate-limit.events", EventType: "rate_limits.updated", Payload: map[string]any{"organization_id": organizationID, "overrides": metadata}}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, item := range applied {
		item.limiter.ApplyOverride(organizationID, item.rate, item.capacity)
	}
	return nil
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.clear(r.Context(), organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clear deletes the organization's overrides, recorded as actor's, then takes
// them off the limiters once that is committed.
func (h *Handler) clear(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := dbgen.New(tx).DeleteRateLimitOverrides(ctx, organizationID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "rate_limits.deleted", "organization", organizationID, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: organizationID, Topic: "rate-limit.events", EventType: "rate_limits.deleted", Payload: map[string]any{"organization_id": organizationID}}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, lim := range []Limiter{h.OrganizationLim, h.UserLim, h.APIKeyLim} {
		lim.ClearOverride(organizationID)
	}
	return nil
}
