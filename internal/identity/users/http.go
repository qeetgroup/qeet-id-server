package user

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// mfaResetter clears a user's MFA factors (admin account-recovery). Kept as an
// interface so the user package needn't import the mfa package.
type mfaResetter interface {
	ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int64, error)
}

// signInEnder ends, inside tx, every way a user is signed in and reports how
// many of each it ended. An interface because the authentication package
// imports this one.
type signInEnder interface {
	EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error)
}

// SignInsEnded counts, by kind, what ending every way a person is signed in
// ended.
type SignInsEnded struct {
	Sessions              int64 // API and console sessions, with their refresh tokens
	LoginSessions         int64 // hosted-login browser sessions
	AppGrants             int64 // applications' refresh grants
	TrustedDevices        int64 // devices remembered to skip the second factor
	PendingAuthorizations int64 // unredeemed codes and uncollected device or CIBA requests
}

// Total is the number of sessions, login sessions and app grants ended.
func (e SignInsEnded) Total() int64 { return e.Sessions + e.LoginSessions + e.AppGrants }

// Handler serves the /users and /me routes. PasswordPolicy checks every
// password it sets; without it setting one fails with 501 rather than store an
// unchecked password. Routes that need MFA or SignIns answer 501 without them,
// and a nil Signals or Mailer announces or emails nothing.
type Handler struct {
	Repo           *Repository
	Validate       *validator.Validate
	PasswordPolicy func(ctx context.Context, tenantID uuid.UUID, email, password string) error
	MFA            mfaResetter
	Signals        *sessionsignal.Signaller
	SignIns        signInEnder
	Mailer         notifier.Sender
	// ActOnCheck refuses changing the account of someone who outranks the
	// caller (rbac.Repository.CheckActOn). Without it every change is refused.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, tenantID, targetID uuid.UUID) error
	// Roles gives a role to the people a bulk import makes. Without it an
	// import can't give one.
	Roles RoleGranter
}

// RoleGranter checks and gives a tenant's role to a new member.
type RoleGranter interface {
	// CheckGrant refuses r's caller giving roleID of tenantID to anyone, and
	// returns the tenant's seat cap for Assign (negative for none); it reads
	// before any transaction.
	CheckGrant(r *http.Request, tenantID, roleID uuid.UUID) (seats int, err error)
	// Assign gives roleID to userID in tenantID, on tx, refusing it with
	// errs.ErrPlanLimit when it takes a seat beyond seats.
	Assign(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, seats int) error
}

// importRole is the role a bulk import gives everyone, with the tenant's seat
// cap read before the import.
type importRole struct {
	ID    uuid.UUID
	Seats int
}

// endEverySignIn ends, inside tx, every way userID is signed in: sessions,
// hosted-login sessions, application grants, trusted devices and pending
// authorizations, so none of them works again if the account comes back. With
// no SignIns it ends the sessions alone.
func (h *Handler) endEverySignIn(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) error {
	if h.SignIns != nil {
		_, err := h.SignIns.EndAllSignIns(ctx, tx, userID, reason)
		return err
	}
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	if err != nil {
		return err
	}
	h.Signals.Revoked(ctx, tx, reason, ended...)
	return nil
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

// Mount registers the user routes on r.
func (h *Handler) Mount(r chi.Router) {
	// /me is the caller's own account, resolved from the principal, so it needs no
	// tenant: a user who belongs to no organisation yet can still use it. Its route
	// policy is user-only, with no permission.
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
	r.Delete("/users/{id}/membership", h.removeMembership)
	r.Delete("/users/{id}/purge", h.purge)

	// User 360 views and actions (user360.go).
	r.Get("/users/{id}/security", h.getSecurity)
	r.Get("/users/{id}/sessions", h.getSessions)
	r.Post("/users/{id}/sessions/revoke-all", h.revokeAllSessions)
	r.Delete("/tenants/{tenantID}/users/{id}/sessions/{sessionID}", h.endSession)
	r.Get("/tenants/{tenantID}/users/{id}/passkeys", h.listPasskeys)
	r.Get("/tenants/{tenantID}/users/{id}/sign-ins", h.signIns)
	r.Delete("/tenants/{tenantID}/users/{id}/passkeys/{passkeyID}", h.removePasskey)
	r.Get("/users/{id}/access", h.getAccess)
	r.Put("/users/{id}/mfa-required", h.setMfaRequired)
}

// standing parses the {id} path param and reports how that user relates to
// the caller's tenant: whether the tenant is their home (it manages the
// account) and whether they hold one of its roles.
func (h *Handler) standing(r *http.Request) (id, tenantID uuid.UUID, home, member bool, err error) {
	id, err = uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, errs.ErrBadRequest.WithDetail("invalid id")
	}
	tenantID, err = httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, err
	}
	home, member, err = h.Repo.StandingIn(r.Context(), id, tenantID)
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, err
	}
	return id, tenantID, home, member, nil
}

// memberID resolves {id} for reading a user: anyone who belongs to the
// caller's tenant, by a role there or by it being their home. Anyone else is
// ErrNotFound, which doesn't leak whether the id exists in another tenant.
func (h *Handler) memberID(r *http.Request) (id, tenantID uuid.UUID, err error) {
	id, tenantID, home, member, err := h.standing(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if !home && !member {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return id, tenantID, nil
}

// scopedID resolves {id} for an action on the whole account (status, password,
// MFA, deletion, signing out everywhere), which only the account's home tenant
// may take. A member from elsewhere is ErrUserManagedElsewhere; anyone else is
// ErrNotFound.
func (h *Handler) scopedID(r *http.Request) (id, tenantID uuid.UUID, err error) {
	id, tenantID, home, member, err := h.standing(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	switch {
	case home:
		return id, tenantID, nil
	case member:
		return uuid.Nil, uuid.Nil, errs.ErrUserManagedElsewhere
	default:
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
}

// actOnID is scopedID for a change to the account, refused when the person
// outranks the caller: only an owner changes an owner, and nobody changes
// someone holding a permission they don't.
func (h *Handler) actOnID(r *http.Request) (id, tenantID uuid.UUID, err error) {
	id, tenantID, err = h.scopedID(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if err := h.checkActOn(r, tenantID, id); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return id, tenantID, nil
}

// checkActOn applies ActOnCheck to the caller of r acting on id in tenantID.
func (h *Handler) checkActOn(r *http.Request, tenantID, id uuid.UUID) error {
	if h.ActOnCheck == nil {
		return errs.ErrNotImplemented
	}
	return h.ActOnCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tenantID, id)
}

// removeMembership removes a member whose home is another tenant from the
// caller's tenant: their roles, groups, sessions, app grants and API keys here,
// with an audit row and event, in one transaction. A home account gets
// ErrUserManagedHere; it is suspended or deleted instead.
func (h *Handler) removeMembership(w http.ResponseWriter, r *http.Request) {
	id, tenantID, home, member, err := h.standing(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	switch {
	case home:
		httpx.WriteError(w, r, errs.ErrUserManagedHere)
		return
	case !member:
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err := h.checkActOn(r, tenantID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.removeMembershipWithEvidence(r, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Removal is what removing a member from a tenant took away.
type Removal struct {
	ID            uuid.UUID `json:"id"`
	RolesRemoved  int64     `json:"roles_removed"`
	SessionsEnded int       `json:"sessions_ended"`
}

func (h *Handler) removeMembershipWithEvidence(r *http.Request, tenantID, userID uuid.UUID) (*Removal, error) {
	ctx := r.Context()
	tx, err := h.Repo.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	roles, err := h.Repo.RemoveFromTenantTx(ctx, tx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	ended, err := sessionsignal.EndUserSessionsInTenant(ctx, tx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	h.Signals.Revoked(ctx, tx, sessionsignal.ReasonRemovedFromOrganization, ended...)
	if err := recordSuspensionEvidence(ctx, tx, r, tenantID, userID, "user.removed_from_organization"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Removal{ID: userID, RolesRemoved: roles, SessionsEnded: len(ended)}, nil
}

// resetMFA clears a user's MFA factors so a locked-out user can enrol again.
// It is audited and the user is emailed.
func (h *Handler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.MFA == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	ctx := r.Context()
	if err := h.refuseSharedCredentials(ctx, id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	target, err := h.Repo.Get(ctx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	removed, err := h.MFA.ResetForUser(ctx, tx, id)
	if err != nil {
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
		Metadata:     map[string]any{"removed": removed},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.tellCredentialChange(ctx, tenantID, target.Email, credentialFactorsReset, "")
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
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, next, err := h.Repo.ListDeleted(r.Context(), *p.TenantID, limit, after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(out, next))
}

// withAudit runs change and its audit row, action on target in tenantID as the
// caller of r, in one transaction: neither commits without the other.
func (h *Handler) withAudit(r *http.Request, tenantID, target uuid.UUID, action string, metadata map[string]any, change func(ctx context.Context, tx pgx.Tx) error) error {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := change(ctx, tx); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, audit.ActorOf(r).Event(tenantID, action, "user", target, metadata)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.withAudit(r, tenantID, id, "user.restored", nil, func(ctx context.Context, tx pgx.Tx) error {
		return h.Repo.RestoreTx(ctx, tx, id)
	}); err != nil {
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

func (h *Handler) purge(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.withAudit(r, tenantID, id, "user.purged", nil, func(ctx context.Context, tx pgx.Tx) error {
		return h.Repo.PurgeTx(ctx, tx, id)
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
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
	filter, err := ParseListFilter(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, next, total, err := h.Repo.List(r.Context(), *p.TenantID, filter, limit, r.URL.Query().Get("cursor"), offset)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":       out,
		"next_cursor": next,
		"total":       total,
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
	u, err := h.createWithEvidence(r, in, hash, nil)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) createWithEvidence(r *http.Request, in CreateInput, passwordHash string, role *importRole) (*User, error) {
	ctx := r.Context()
	if err := domainverify.CheckNewAccount(ctx, h.Repo.Pool(), in.TenantID, in.Email); err != nil {
		return nil, err
	}
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
		Payload:     map[string]any{"user_id": u.ID, "tenant_id": u.TenantID, "email": u.Email, "source": "admin"},
	}); err != nil {
		return nil, err
	}
	if role != nil {
		if err := h.Roles.Assign(ctx, tx, u.ID, tenant, role.ID, actorID, role.Seats); err != nil {
			return nil, err
		}
		if err := audit.Record(ctx, tx, audit.Event{TenantID: &tenant, ActorUserID: actorID, ActorType: actorType,
			Action: "role.assigned", ResourceType: "user", ResourceID: &id, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(),
			RequestID: httpx.RequestID(r), Metadata: map[string]any{"role_id": role.ID, "source": "bulk_import"}}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	u, err := h.Repo.Get(ctx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	member, err := h.Repo.Member(ctx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u.Roles, u.AssignedRoles, u.MfaEnabled, u.GroupsCount = member.Roles, member.AssignedRoles, member.MfaEnabled, member.GroupsCount
	u.LastSeenAt, u.LastSeenIP, u.HomeTenantName = member.LastSeenAt, member.LastSeenIP, member.HomeTenantName
	if u.Suspension, err = h.Repo.SuspensionOf(ctx, tenantID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u.SeenBy(tenantID))
}

// me returns the caller's own user record, resolved from the principal rather
// than the path. It needs no tenant.
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

// updateMe updates the caller's own display name, avatar and locale. Other
// UpdateInput fields in the body (status, phone, metadata) are ignored, so a
// user can't change their own standing.
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
	id, tenantID, err := h.actOnID(r)
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
	u, err := h.updateWithEvidence(r, tenantID, id, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.softDeleteWithEvidence(r, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// softDeleteWithEvidence, in one transaction, soft-deletes a user (recording who
// did it), ends and announces all their sessions, and records an audit row and
// a user.deleted event. Restoring the account brings no session back.
func (h *Handler) softDeleteWithEvidence(r *http.Request, tenantID, userID uuid.UUID) (*Deletion, error) {
	ctx := r.Context()
	tx, err := h.Repo.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var actor *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actor = p.UserID
	}
	d, err := h.Repo.SoftDeleteByTx(ctx, tx, userID, actor)
	if err != nil {
		return nil, err
	}
	if err := h.endEverySignIn(ctx, tx, userID, sessionsignal.ReasonDeleted); err != nil {
		return nil, err
	}
	if err := recordSuspensionEvidence(ctx, tx, r, tenantID, userID, "user.deleted"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

type setPasswordInput struct {
	Password string `json:"password" validate:"required,max=256"` // length + rules: PasswordPolicy
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.SignIns == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
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
	if err := h.refuseSharedCredentials(r.Context(), id, tenantID); err != nil {
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
	h.tellCredentialChange(r.Context(), tenantID, target.Email, credentialPasswordSet, "")
	w.WriteHeader(http.StatusNoContent)
}

// setPasswordWithEvidence, in one transaction, ends every way userID is signed
// in (as revokeAllSessions does), sets their password hash, and records an audit
// row and a user.password_set event. An administrator's reset is usually
// incident response, so no session, application grant or trusted device survives.
func (h *Handler) setPasswordWithEvidence(r *http.Request, tenantID, userID uuid.UUID, hash string) error {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Unlike the self-service change there is no session to keep: the caller is
	// a different person from the account holder.
	ended, err := h.SignIns.EndAllSignIns(ctx, tx, userID, sessionsignal.ReasonAdminPasswordSet)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
		    password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, userID, hash); err != nil {
		return err
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
		Metadata: map[string]any{
			"sessions_revoked":             true,
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
		},
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
