package user

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// mfaResetter clears a user's MFA factors (admin account-recovery). Kept as an
// interface so the user package needn't import the mfa package.
type mfaResetter interface {
	ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error
}

// signInEnder ends, inside tx, every way a user is signed in — API and console
// sessions, hosted-login browser sessions and applications' refresh grants —
// and reports how many of each it ended (admin force sign-out). Kept as an
// interface because the authentication package imports this one.
type signInEnder interface {
	EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error)
}

// SignInsEnded counts what ending every way a person is signed in ended
// (signInEnder.EndAllSignIns, the administrator's force sign-out and the
// person's own sign out everywhere).
type SignInsEnded struct {
	// Sessions are API and console sessions; ending one is what makes its
	// refresh tokens stop working.
	Sessions int64
	// LoginSessions are hosted-login browser sessions.
	LoginSessions int64
	// AppGrants are the refresh grants applications hold, counted once per
	// grant.
	AppGrants int64
	// TrustedDevices are devices remembered so they skip the second factor.
	TrustedDevices int64
	// PendingAuthorizations are unredeemed authorisation codes and device or
	// back-channel sign-in requests that were pending or approved but not yet
	// collected.
	PendingAuthorizations int64
}

// Total is the number of sign-ins ended, all places together.
func (e SignInsEnded) Total() int64 { return e.Sessions + e.LoginSessions + e.AppGrants }

type Handler struct {
	Repo     *Repository
	Validate *validator.Validate
	// PasswordPolicy is the password check every password this handler sets
	// goes through (admin create, bulk import, admin set-password): the
	// tenant's rules, the offline strength baseline and, when enabled, the
	// breach check. Required to set a password — nil refuses (501) rather than
	// store an unchecked one. A function so the user package needn't depend on
	// the authpolicy package (authpolicy.Service.ValidateForTenant).
	PasswordPolicy func(ctx context.Context, tenantID uuid.UUID, email, password string) error
	// MFA resets a user's second factors (admin recovery). Optional.
	MFA mfaResetter
	// Signals announces the sessions an account change ends (nil = announces
	// nothing).
	Signals *sessionsignal.Signaller
	// SignIns ends every way a user is signed in (admin force sign-out).
	// Without it that route answers 501.
	SignIns signInEnder
}

// hashNewPassword checks a password for an account in tenantID with the given
// email, then hashes it.
func (h *Handler) hashNewPassword(ctx context.Context, tenantID uuid.UUID, email, plain string) (string, error) {
	if h.PasswordPolicy == nil {
		return "", errs.ErrNotImplemented
	}
	if err := h.PasswordPolicy(ctx, tenantID, email, plain); err != nil {
		return "", err
	}
	return password.Hash(plain)
}

func (h *Handler) Mount(r chi.Router) {
	// Self-service: the authenticated caller's own account. Resolves the target
	// from the auth principal, so it needs NO tenant — a tenant-less user (fresh
	// signup, before they create/join a workspace) can still read/update their
	// own profile. Deliberately absent from permissionMap so rbac.Enforce lets it
	// through, and it carries no {tenantID} param so EnforceTenantScope ignores it.
	r.Get("/me", h.me)
	r.Patch("/me", h.updateMe)

	r.Get("/users", h.list)
	r.Get("/users/stats", h.getUserStats)
	r.Get("/users/trends", h.getUserTrends)
	r.Get("/users/deleted", h.listDeleted)
	r.Get("/users/suspended", h.listSuspended)
	r.Post("/users/{id}/reactivate", h.reactivateUser)
	r.Put("/users/{id}/suspension", h.reviewSuspension)
	r.Post("/users", h.create)
	r.Post("/users/bulk", h.bulkCreate)
	r.Post("/users/bulk/import", h.bulkImportFromVendor)
	r.Get("/users/{id}", h.get)
	r.Patch("/users/{id}", h.update)
	r.Delete("/users/{id}", h.delete)
	r.Post("/users/{id}/password", h.setPassword)
	r.Delete("/users/{id}/mfa", h.resetMFA)
	r.Post("/users/{id}/restore", h.restore)
	r.Delete("/users/{id}/purge", h.purge)

	// User 360 — admin read surfaces (+ one force-sign-out mutation). See user360.go.
	r.Get("/users/{id}/security", h.getSecurity)
	r.Get("/users/{id}/sessions", h.getSessions)
	r.Post("/users/{id}/sessions/revoke-all", h.revokeAllSessions)
	r.Get("/users/{id}/access", h.getAccess)
	r.Put("/users/{id}/mfa-required", h.setMfaRequired)
}

// scopedID parses the {id} path param AND enforces that the target user belongs
// to the caller's own tenant, returning ErrNotFound on any cross-tenant access
// (QID-18 — previously every by-id user handler operated on the raw id with no
// tenant scoping, so a tenant admin could read/modify/delete another tenant's
// users by id). ErrNotFound (not Forbidden) is deliberate: it doesn't leak
// whether the id exists in some other tenant.
func (h *Handler) scopedID(r *http.Request) (id, tenantID uuid.UUID, err error) {
	id, err = uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid id")
	}
	tenantID, err = httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	owner, err := h.Repo.TenantOf(r.Context(), id)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if owner != tenantID {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return id, tenantID, nil
}

// resetMFA clears a user's MFA factors so a locked-out user can re-enroll.
// Admin-only (gated on user.write by the RBAC enforcer); audited.
func (h *Handler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.MFA == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.MFA.ResetForUser(ctx, tx, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		Action:       "mfa.admin_reset",
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "The user's multi-factor authentication has been reset. They can re-enroll at next sign-in.",
	})
}

func (h *Handler) listDeleted(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := h.Repo.ListDeleted(r.Context(), *p.TenantID, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// auditUserAction records a best-effort audit row for a recycle-bin action.
func (h *Handler) auditUserAction(r *http.Request, action string, target uuid.UUID) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	p := httpx.PrincipalFromCtx(ctx)
	var actorID *uuid.UUID
	var tenantID *uuid.UUID
	if p != nil {
		actorID = p.UserID
		tenantID = p.TenantID
	}
	id := target
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  actorID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.Restore(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "user.restored", id)
	u, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) purge(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.Purge(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "user.purged", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	out, next, err := h.Repo.ListByTenant(r.Context(), *p.TenantID, limit, r.URL.Query().Get("cursor"), offset)
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
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// The password is checked before anything is written, so a refused one
	// leaves no user row behind.
	var hash string
	if in.Password != "" {
		ph, err := h.hashNewPassword(r.Context(), tenantID, in.Email, in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		hash = ph
	}
	u, err := h.createWithEvidence(r, in, hash)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) createWithEvidence(r *http.Request, in CreateInput, passwordHash string) (*User, error) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	u, err := h.Repo.CreateWithCredentialTx(ctx, tx, in, passwordHash)
	if err != nil {
		return nil, err
	}
	actor := httpx.PrincipalFromCtx(ctx)
	var actorID *uuid.UUID
	actorType := "system"
	if actor != nil {
		actorID = actor.UserID
		if actor.ActorType != "" {
			actorType = actor.ActorType
		}
	}
	id := u.ID
	tenant := u.TenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenant,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "user.created",
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"email": u.Email},
	}); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: u.ID,
		Topic:       "user.events",
		EventType:   "user.created",
		Payload:     u,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// me returns the authenticated caller's own user record. Unlike get, it resolves
// the id from the auth principal (not the path) and needs no tenant — this is the
// "My Account" self-service read, usable before a user belongs to any workspace.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	u, err := h.Repo.Get(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// updateMe patches the caller's own profile. Only self-editable fields are
// honoured (display name + avatar); privileged fields on UpdateInput (status,
// phone, metadata) are ignored here, so a user can't change their own standing
// through the self-service surface.
func (h *Handler) updateMe(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Restrict to self-editable profile fields regardless of what the body carried.
	safe := UpdateInput{DisplayName: in.DisplayName, AvatarURL: in.AvatarURL, Locale: in.Locale}
	if err := h.Validate.Struct(safe); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// Locale lives in the metadata blob (not a column). Update replaces metadata
	// wholesale, so merge onto the current value to preserve any other keys.
	if in.Locale != nil {
		cur, err := h.Repo.Get(r.Context(), *p.UserID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		meta := make(map[string]any, len(cur.Metadata)+1)
		for k, v := range cur.Metadata {
			meta[k] = v
		}
		meta["locale"] = *in.Locale
		safe.Metadata = meta
	}
	u, err := h.Repo.Update(r.Context(), *p.UserID, safe)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	var u *User
	if in.Status != nil {
		u, err = h.updateStatusWithEvidence(r, tenantID, id, in)
	} else {
		u, err = h.Repo.Update(r.Context(), id, in)
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.SoftDelete(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setPasswordInput struct {
	Password string `json:"password" validate:"required,max=256"` // length + rules: PasswordPolicy
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in setPasswordInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	target, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	hash, err := h.hashNewPassword(r.Context(), tenantID, target.Email, in.Password)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.setPasswordWithEvidence(r, tenantID, id, hash); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setPasswordWithEvidence writes the credential, evicts the target's sessions,
// and records the act — all in one transaction.
//
// An administrator resetting a password is nearly always incident response, so
// leaving the compromised sessions live defeats the point of the reset. This is
// the same guarantee ChangePassword gives for self-service; the two paths had
// drifted, and this one additionally recorded nothing at all.
func (h *Handler) setPasswordWithEvidence(r *http.Request, tenantID, userID uuid.UUID, hash string) error {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
		    password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, userID, hash); err != nil {
		return err
	}
	// Every session, including any the admin is not aware of. Unlike the
	// self-service change there is no session to preserve here: the caller is a
	// different person from the account holder.
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	if err != nil {
		return err
	}
	h.Signals.Revoked(ctx, tx, sessionsignal.ReasonAdminPasswordSet, ended...)

	actor := httpx.PrincipalFromCtx(ctx)
	var actorID *uuid.UUID
	actorType := "system"
	if actor != nil {
		actorID = actor.UserID
		if actor.ActorType != "" {
			actorType = actor.ActorType
		}
	}
	target := userID
	tenant := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenant,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "user.password_set",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"sessions_revoked": true},
	}); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: userID,
		Topic:       "user.events",
		EventType:   "user.password_set",
		Payload: map[string]any{
			"user_id": userID, "tenant_id": tenantID, "sessions_revoked": true,
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
