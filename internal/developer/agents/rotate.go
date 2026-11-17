package agent

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/developer/agents/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Rotation overlaps: how long a replaced secret goes on working beside its
// replacement, by default and at most.
const (
	DefaultRotationOverlap = 24 * time.Hour
	MaxRotationOverlap     = 7 * 24 * time.Hour
)

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// previousSecretWorks reports whether secret is the one replaced at the last
// rotation and its overlap hasn't ended.
func previousSecretWorks(ctx context.Context, hash *string, until pgtype.Timestamptz, secret string) (bool, error) {
	if hash == nil || !until.Valid || !until.Time.After(time.Now()) {
		return false, nil
	}
	ok, _, err := password.VerifySecret(ctx, *hash, secret)
	return ok, err
}

// RotateSecret gives one of the organization's agents that isn't decommissioned a new
// secret, returned only now, and leaves the old one working for overlap (0: it
// stops at once). Recorded as actor's.
func (s *Service) RotateSecret(ctx context.Context, organizationID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (string, time.Time, error) {
	if overlap < 0 || overlap > MaxRotationOverlap {
		return "", time.Time{}, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "overlap_hours", Code: "out_of_range", Message: "Keep the old secret working for 0 to 168 hours.",
		}})
	}
	secret, err := newSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(overlap)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).RotateAgentSecret(ctx, dbgen.RotateAgentSecretParams{
		PreviousExpiresAt: pgtype.Timestamptz{Time: until, Valid: true}, SecretHash: password.HashSecret(secret),
		ID: id, OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, errs.ErrAgentNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.secret_rotated", "agent", id,
		map[string]any{"name": name, "old_secret_ends": until})); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return secret, until, nil
}

// ResumeAll makes every suspended agent of an organization active again in one
// statement, the undoing of KillAll. Returns the number resumed and emits a
// single webhook event.
func (s *Service) ResumeAll(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).ResumeAllAgents(ctx, organizationID)
	if err != nil {
		return 0, err
	}
	count := int(n)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.resume_all", "tenant", organizationID,
		map[string]any{"resumed": count})); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: organizationID, Topic: "agent.events", EventType: "agent.resume_all",
		Payload: map[string]any{"tenant_id": organizationID, "resumed": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

// overlapOf reads a rotation request's overlap_hours, the default when absent.
func overlapOf(r *http.Request) (time.Duration, error) {
	var in struct {
		OverlapHours *int `json:"overlap_hours"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			return 0, err
		}
	}
	if in.OverlapHours == nil {
		return DefaultRotationOverlap, nil
	}
	return time.Duration(*in.OverlapHours) * time.Hour, nil
}

// rotateSecret handles POST /v1/tenants/{tenantID}/agents/{id}/rotate-secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
		return
	}
	overlap, err := overlapOf(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The new secret carries the credential's scopes, so whoever rotates it
	// must hold them, as for creating one.
	if err := h.checkScopes(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	secret, until, err := h.Service.RotateSecret(r.Context(), organizationID, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "secret": secret, "previous_secret_expires_at": until,
	})
}

// resumeAll handles POST /v1/tenants/{tenantID}/agents/resume-all.
func (h *Handler) resumeAll(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.ResumeAll(r.Context(), organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resumed": n})
}

// Scopes returns the scopes of agent id of organizationID, or ErrAgentNotFound.
func (s *Service) Scopes(ctx context.Context, organizationID, id uuid.UUID) ([]string, error) {
	scopes, err := s.q.AgentScopes(ctx, dbgen.AgentScopesParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAgentNotFound
	}
	return scopes, err
}

// checkScopes refuses the caller taking over credential id's scopes in
// organizationID (GrantCheck); without the check it refuses every caller.
func (h *Handler) checkScopes(r *http.Request, organizationID, id uuid.UUID) error {
	if h.GrantCheck == nil {
		return errs.ErrNotImplemented
	}
	scopes, err := h.Service.Scopes(r.Context(), organizationID, id)
	if err != nil {
		return err
	}
	return h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, scopes)
}
