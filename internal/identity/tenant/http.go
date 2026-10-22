package tenant

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// tokenIssuer is the part of auth.Service this handler needs.
type tokenIssuer interface {
	IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*auth.TokenPair, error)
}

// Handler serves the /tenants routes and /me/organizations. AuthService, if
// set, issues a token pair for a newly created tenant so the client can switch
// in; a nil Signals announces no ended sessions.
type Handler struct {
	Repo        *Repository
	Validate    *validator.Validate
	AuthService tokenIssuer
	Signals     *sessionsignal.Signaller
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants", h.list)
	r.Get("/me/organizations", h.eligibleOrganizations)
	r.Post("/tenants", h.create)
	// {tenantID}, not {id}, so EnforceTenantScope rejects any path tenant other
	// than the caller's; rbac.Enforce checks only the caller's active tenant.
	r.Get("/tenants/{tenantID}", h.get)
	r.Patch("/tenants/{tenantID}", h.update)
	r.Delete("/tenants/{tenantID}", h.delete)
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

	// Mint a pair scoped to the new tenant so the caller switches in; tenant still returned if it fails.
	resp := map[string]any{
		"tenant":    t,
		"tenant_id": t.ID,
		"roles":     []string{"owner"},
	}
	if h.AuthService != nil {
		if pair, err := h.AuthService.IssuePair(r.Context(), *p.UserID, t.ID, httpx.ClientIP(r), r.UserAgent(), "tenant_create"); err == nil {
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
	t, err := h.Repo.Update(r.Context(), id, in, h.lifecycle(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	if err := h.Repo.SoftDelete(r.Context(), id, h.lifecycle(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// lifecycle returns the StatusChange run when an organisation's status changes.
// Suspending or deleting it ends and announces every session in it;
// reactivating restores none. Each change is audited and queued as an event.
// Access tokens already issued last out their short lifetime.
func (h *Handler) lifecycle(r *http.Request) StatusChange {
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
		id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
		if err != nil {
			return errs.ErrBadRequest.WithDetail("invalid tenantID")
		}
		ended := 0
		if reason != "" {
			sessions, err := sessionsignal.EndTenantSessions(ctx, tx, id)
			if err != nil {
				return err
			}
			h.Signals.Revoked(ctx, tx, reason, sessions...)
			ended = len(sessions)
		}
		var actor *uuid.UUID
		actorType := "system"
		if p := httpx.PrincipalFromCtx(ctx); p != nil {
			actor = p.UserID
			if p.ActorType != "" {
				actorType = p.ActorType
			}
		}
		meta := map[string]any{"from": from, "status": to, "sessions_ended": ended}
		if err := audit.Record(ctx, tx, audit.Event{TenantID: &id, ActorUserID: actor, ActorType: actorType, Action: action,
			ResourceType: "tenant", ResourceID: &id, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
			Metadata: meta}); err != nil {
			return err
		}
		return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "tenant.events", EventType: action,
			Payload: map[string]any{"tenant_id": id, "status": to, "from": from}})
	}
}
