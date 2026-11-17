package principal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/developer/principal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Rotation overlaps: how long a replaced secret goes on working beside its
// replacement, by default and at most.
const (
	DefaultRotationOverlap = 24 * time.Hour
	MaxRotationOverlap     = 7 * 24 * time.Hour
)

// previousSecretWorks reports whether secret is the one replaced at the last
// rotation and its overlap hasn't ended.
func previousSecretWorks(ctx context.Context, hash *string, until pgtype.Timestamptz, secret string) (bool, error) {
	if hash == nil || !until.Valid || !until.Time.After(time.Now()) {
		return false, nil
	}
	ok, _, err := password.VerifySecret(ctx, *hash, secret)
	return ok, err
}

// RotateSecret gives one of the tenant's service principals a new secret,
// returned only now, and leaves the old one working for overlap (0: it stops
// at once). Recorded as actor's.
func (s *Service) RotateSecret(ctx context.Context, tenantID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (string, time.Time, error) {
	if overlap < 0 || overlap > MaxRotationOverlap {
		return "", time.Time{}, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "overlap_hours", Code: "out_of_range", Message: "Keep the old secret working for 0 to 168 hours.",
		}})
	}
	raw, _, err := codes.URLToken()
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(overlap)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).RotateServicePrincipalSecret(ctx, dbgen.RotateServicePrincipalSecretParams{
		PreviousExpiresAt: pgtype.Timestamptz{Time: until, Valid: true}, SecretHash: password.HashSecret(raw),
		ID: id, TenantID: tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, errs.ErrPrincipalNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "service_principal.secret_rotated", "service_principal", id,
		map[string]any{"name": name, "old_secret_ends": until})); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return raw, until, nil
}

// Enable turns one of the tenant's disabled service principals back on,
// recorded as actor's. Enabling one that is on changes nothing.
func (s *Service) Enable(ctx context.Context, tenantID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).EnableServicePrincipal(ctx, dbgen.EnableServicePrincipalParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrPrincipalNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "service_principal.enabled", "service_principal", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
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

// pathIDs returns the tenant and service principal a request names.
func pathIDs(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	tid, err := httpx.PathTenantOr(r, errs.ErrPrincipalInvalidID, errs.ErrForbidden)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrPrincipalInvalidID
	}
	return tid, id, nil
}

// rotateSecret handles POST /v1/tenants/{tenantID}/service-principals/{id}/rotate-secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	tid, id, err := pathIDs(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	overlap, err := overlapOf(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The new secret carries the credential's scopes, so whoever rotates it
	// must hold them, as for creating one.
	if err := h.checkScopes(r, tid, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	secret, until, err := h.Service.RotateSecret(r.Context(), tid, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"previous_secret_expires_at": until,
		"warning":                    "secret shown once",
	})
}

// enable handles POST /v1/tenants/{tenantID}/service-principals/{id}/enable.
func (h *Handler) enable(w http.ResponseWriter, r *http.Request) {
	tid, id, err := pathIDs(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Enable(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Scopes returns the scopes of service principal id of tenantID, or ErrPrincipalNotFound.
func (s *Service) Scopes(ctx context.Context, tenantID, id uuid.UUID) ([]string, error) {
	scopes, err := s.q.ServicePrincipalScopes(ctx, dbgen.ServicePrincipalScopesParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrPrincipalNotFound
	}
	return scopes, err
}

// checkScopes refuses the caller taking over credential id's scopes in
// tenantID (GrantCheck); without the check it refuses every caller.
func (h *Handler) checkScopes(r *http.Request, tenantID, id uuid.UUID) error {
	if h.GrantCheck == nil {
		return errs.ErrNotImplemented
	}
	scopes, err := h.Service.Scopes(r.Context(), tenantID, id)
	if err != nil {
		return err
	}
	return h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tenantID, scopes)
}
