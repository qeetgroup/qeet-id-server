package tenant

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// tokenIssuer is the part of auth.Service this handler needs.
type tokenIssuer interface {
	EnterCreatedTenant(ctx context.Context, userID, tenantID, fromSessionID uuid.UUID, ip, ua string) (*auth.TokenPair, error)
}

// Handler serves the /tenants routes and /me/organizations. AuthService, if
// set, issues a token pair for a newly created tenant so the client can switch
// in, continuing the caller's session; a nil Signals announces no ended
// sessions.
type Handler struct {
	Repo        *Repository
	Validate    *validator.Validate
	AuthService tokenIssuer
	Signals     *sessionsignal.Signaller
	// OwnerCheck reports whether a person owns an organisation
	// (rbac.Repository.IsOwner). Only an owner deletes one, calls off its
	// deletion or changes its status; without it those are refused.
	OwnerCheck func(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
}

// requireOwner refuses, with ErrTenantOwnerOnly, a caller who isn't a person
// owning tenant id.
func (h *Handler) requireOwner(r *http.Request, id uuid.UUID) error {
	if h.OwnerCheck == nil {
		return errs.ErrNotImplemented
	}
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || (p.ActorType != "" && p.ActorType != "user") {
		return errs.ErrTenantOwnerOnly
	}
	owner, err := h.OwnerCheck(r.Context(), *p.UserID, id)
	if err != nil {
		return err
	}
	if !owner {
		return errs.ErrTenantOwnerOnly
	}
	return nil
}

// Mount registers the organisation routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants", h.list)
	r.Get("/me/organizations", h.eligibleOrganizations)
	r.Post("/tenants", h.create)
	// {tenantID}, not {id}, so EnforceTenantScope rejects any path tenant other
	// than the caller's; rbac.Enforce checks only the caller's active tenant.
	r.Get("/tenants/{tenantID}", h.get)
	r.Patch("/tenants/{tenantID}", h.update)
	r.Delete("/tenants/{tenantID}", h.delete)
	r.Post("/tenants/{tenantID}/deletion/cancel", h.cancelDeletion)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, next, err := h.Repo.List(r.Context(), *p.UserID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":       out,
		"next_cursor": next,
	})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	// The new organisation's rows aren't the caller's current organisation's.
	r = r.WithContext(postgres.AcrossTenants(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// Only the free plan may be self-provisioned here: paid plans go through
	// signup checkout so payment is captured first, and enterprise is sales-led.
	if in.Plan != "" && in.Plan != "free" {
		httpx.WriteError(w, r, errs.ErrBillingCheckoutRequired)
		return
	}
	// Require a verified email before spinning up an org: it becomes the owner's
	// account of record for billing, recovery, and every downstream notification.
	if verified, err := h.Repo.IsEmailVerified(r.Context(), *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	} else if !verified {
		httpx.WriteError(w, r, errs.ErrEmailNotVerified)
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	// The tenant, owner role/membership, audit row, and outbox event are one
	// durable mutation.
	t, err := h.Repo.CreateWithOwnerTx(ctx, tx, in, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := t.ID
	actorType := p.ActorType
	if actorType == "" {
		actorType = "user"
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &id, ActorUserID: p.UserID, ActorType: actorType,
		Action: "tenant.created", ResourceType: "tenant", ResourceID: &id,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"slug": t.Slug, "name": t.Name},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: t.ID, Topic: "tenant.events", EventType: "tenant.created", Payload: t,
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// Mint a pair scoped to the new tenant so the caller switches in; tenant
	// still returned if it fails. It continues the caller's session, so
	// creating an organisation never lengthens a sign-in.
	resp := map[string]any{
		"tenant":    t,
		"tenant_id": t.ID,
		"roles":     []string{"owner"},
	}
	if h.AuthService != nil && p.SessionID != nil {
		if pair, err := h.AuthService.EnterCreatedTenant(r.Context(), *p.UserID, t.ID, *p.SessionID, httpx.ClientIP(r), r.UserAgent()); err == nil {
			resp["access_token"] = pair.AccessToken
			resp["token_type"] = pair.TokenType
			resp["expires_at"] = pair.ExpiresAt
			resp["refresh_token"] = pair.RefreshToken
			resp["session_id"] = pair.SessionID
			resp["user_id"] = pair.UserID
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	t, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// Changing an organisation's status is an owner's. Suspending it would
	// lock out every member, its owners too, with nobody left to undo it.
	if in.Status != nil {
		if err := h.requireOwner(r, id); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if *in.Status == "suspended" {
			httpx.WriteError(w, r, errs.ErrTenantSelfSuspend)
			return
		}
	}
	t, err := h.Repo.Update(r.Context(), id, in, h.lifecycle(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

// delete schedules the organisation's deletion, which an owner can call off
// until it is due; the background job deletes it then (DeleteDue).
func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	if err := h.requireOwner(r, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actor := audit.ActorOf(r)
	due, err := h.Repo.ScheduleDeletion(r.Context(), id, func(ctx context.Context, tx pgx.Tx, due time.Time) error {
		return recordDeletion(ctx, tx, actor, id, "tenant.deletion_scheduled", map[string]any{"deletion_due_at": due})
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"tenant_id": id, "deletion_due_at": due})
}

// cancelDeletion calls off the organisation's scheduled deletion.
func (h *Handler) cancelDeletion(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	if err := h.requireOwner(r, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actor := audit.ActorOf(r)
	if err := h.Repo.CancelDeletion(r.Context(), id, func(ctx context.Context, tx pgx.Tx) error {
		return recordDeletion(ctx, tx, actor, id, "tenant.deletion_cancelled", nil)
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

// recordDeletion audits and queues a change to an organisation's scheduled
// deletion, inside its transaction.
func recordDeletion(ctx context.Context, tx pgx.Tx, actor audit.Actor, id uuid.UUID, action string, meta map[string]any) error {
	if err := audit.Record(ctx, tx, actor.Event(id, action, "tenant", id, meta)); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "tenant.events", EventType: action,
		Payload: map[string]any{"tenant_id": id, "deletion_due_at": meta["deletion_due_at"]}})
}

// DeleteDue deletes every organisation whose scheduled deletion is due, as
// the system, ending and announcing its sessions through signals (nil: none).
func DeleteDue(ctx context.Context, repo *Repository, signals *sessionsignal.Signaller) (int, error) {
	ids, err := repo.DueForDeletion(ctx, 100)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, id := range ids {
		err := repo.SoftDelete(ctx, id, statusChange(signals, id, audit.Actor{Type: "system"}))
		if errors.Is(err, errs.ErrNotFound) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

// lifecycle returns the StatusChange run when an organisation's status
// changes in r.
func (h *Handler) lifecycle(r *http.Request) StatusChange {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return func(context.Context, pgx.Tx, string, string) error {
			return errs.ErrBadRequest.WithDetail("invalid tenantID")
		}
	}
	return statusChange(h.Signals, id, audit.ActorOf(r))
}

// statusChange returns the StatusChange run when organisation id's status
// changes, by actor. Suspending or deleting it ends and announces every
// session in it; reactivating restores none, and the ended sessions' access
// tokens are refused from then on. Each change is audited and queued as an
// event.
func statusChange(signals *sessionsignal.Signaller, id uuid.UUID, actor audit.Actor) StatusChange {
	return func(ctx context.Context, tx pgx.Tx, from, to string) error {
		var action, reason string
		switch to {
		case "suspended":
			action, reason = "tenant.suspended", sessionsignal.ReasonTenantSuspended
		case "deleted":
			action, reason = "tenant.deleted", sessionsignal.ReasonTenantDeleted
		case "active":
			action = "tenant.reactivated"
		default:
			return nil
		}
		ended := 0
		if reason != "" {
			sessions, err := sessionsignal.EndTenantSessions(ctx, tx, id)
			if err != nil {
				return err
			}
			signals.Revoked(ctx, tx, reason, sessions...)
			ended = len(sessions)
		}
		meta := map[string]any{"from": from, "status": to, "sessions_ended": ended}
		if err := audit.Record(ctx, tx, actor.Event(id, action, "tenant", id, meta)); err != nil {
			return err
		}
		return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "tenant.events", EventType: action,
			Payload: map[string]any{"tenant_id": id, "status": to, "from": from}})
	}
}
