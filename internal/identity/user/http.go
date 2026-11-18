package user

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
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

// Handler serves the /users and /me routes. PasswordPolicy checks every
// password it sets; without it setting one fails with 501 rather than store an
// unchecked password. Routes that need MFA or SignIns answer 501 without them,
// and a nil Signals or Mailer announces or emails nothing.
type Handler struct {
	Repo           *Repository
	Validate       *validator.Validate
	PasswordPolicy func(ctx context.Context, organizationID uuid.UUID, email, password string) error
	MFA            mfaResetter
	Signals        *sessionsignal.Signaller
	SignIns        signInEnder
	Mailer         notifier.Sender
	// ActOnCheck refuses changing the account of someone who outranks the
	// caller (rbac.Repository.CheckActOn). Without it every change is refused.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error
	// Roles gives a role to the people a bulk import makes. Without it an
	// import can't give one.
	Roles RoleGranter
}

// RoleGranter checks and gives an organization's role to a new member.
type RoleGranter interface {
	// CheckGrant refuses r's caller giving roleID of organizationID to anyone, and
	// returns the organization's seat cap for Assign (negative for none); it reads
	// before any transaction.
	CheckGrant(r *http.Request, organizationID, roleID uuid.UUID) (seats int, err error)
	// Assign gives roleID to userID in organizationID, on tx, refusing it with
	// errs.ErrPlanLimit when it takes a seat beyond seats.
	Assign(ctx context.Context, tx pgx.Tx, userID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, seats int) error
}

// importRole is the role a bulk import gives everyone, with the organization's seat
// cap read before the import.
type importRole struct {
	ID    uuid.UUID
	Seats int
}

// hashNewPassword checks a password for an account in organizationID with the given
// email, then hashes it.
func (h *Handler) hashNewPassword(ctx context.Context, organizationID uuid.UUID, email, plain string) (string, error) {
	if h.PasswordPolicy == nil {
		return "", errs.ErrNotImplemented
	}
	if err := h.PasswordPolicy(ctx, organizationID, email, plain); err != nil {
		return "", err
	}
	return password.Hash(plain)
}

// Mount registers the user routes on r.
func (h *Handler) Mount(r chi.Router) {
	// /me is the caller's own account, resolved from the principal, so it needs no
	// organization: a user who belongs to no organization yet can still use it. Its route
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
	r.Delete("/organizations/{organizationID}/users/{id}/sessions/{sessionID}", h.endSession)
	r.Get("/organizations/{organizationID}/users/{id}/passkeys", h.listPasskeys)
	r.Get("/organizations/{organizationID}/users/{id}/sign-ins", h.signIns)
	r.Delete("/organizations/{organizationID}/users/{id}/passkeys/{passkeyID}", h.removePasskey)
	r.Get("/users/{id}/access", h.getAccess)
	r.Put("/users/{id}/mfa-required", h.setMfaRequired)
}

// standing parses the {id} path param and reports how that user relates to
// the caller's organization: whether the organization is their home (it manages the
// account) and whether they hold one of its roles.
func (h *Handler) standing(r *http.Request) (id, organizationID uuid.UUID, home, member bool, err error) {
	id, err = httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, err
	}
	organizationID, err = httpx.RequireOrganization(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, err
	}
	home, member, err = h.Repo.StandingIn(r.Context(), id, organizationID)
	if err != nil {
		return uuid.Nil, uuid.Nil, false, false, err
	}
	return id, organizationID, home, member, nil
}

// memberID resolves {id} for reading a user: anyone who belongs to the
// caller's organization, by a role there or by it being their home. Anyone else is
// ErrNotFound, which doesn't leak whether the id exists in another organization.
func (h *Handler) memberID(r *http.Request) (id, organizationID uuid.UUID, err error) {
	id, organizationID, home, member, err := h.standing(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if !home && !member {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return id, organizationID, nil
}

// scopedID resolves {id} for an action on the whole account (status, password,
// MFA, deletion, signing out everywhere), which only the account's home organization
// may take. A member from elsewhere is ErrUserManagedElsewhere; anyone else is
// ErrNotFound.
func (h *Handler) scopedID(r *http.Request) (id, organizationID uuid.UUID, err error) {
	id, organizationID, home, member, err := h.standing(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	switch {
	case home:
		return id, organizationID, nil
	case member:
		return uuid.Nil, uuid.Nil, errs.ErrUserManagedElsewhere
	default:
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
}

// actOnID is scopedID for a change to the account, refused when the person
// outranks the caller: only an owner changes an owner, and nobody changes
// someone holding a permission they don't.
func (h *Handler) actOnID(r *http.Request) (id, organizationID uuid.UUID, err error) {
	id, organizationID, err = h.scopedID(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if err := h.checkActOn(r, organizationID, id); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return id, organizationID, nil
}

// checkActOn applies ActOnCheck to the caller of r acting on id in organizationID.
func (h *Handler) checkActOn(r *http.Request, organizationID, id uuid.UUID) error {
	if h.ActOnCheck == nil {
		return errs.ErrNotImplemented
	}
	return h.ActOnCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, id)
}

// removeMembership removes a member whose home is another organization from the
// caller's organization: their roles, groups, sessions, app grants and API keys here,
// with an audit row and event, in one transaction. A home account gets
// ErrUserManagedHere; it is suspended or deleted instead.
func (h *Handler) removeMembership(w http.ResponseWriter, r *http.Request) {
	id, organizationID, home, member, err := h.standing(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	switch {
	case home:
		httpx.WriteError(w, r, ErrManagedHere)
		return
	case !member:
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err := h.checkActOn(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.accounts().removeMembership(r.Context(), organizationID, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// resetMFA clears a user's MFA factors so a locked-out user can enrol again.
// It is audited and the user is emailed.
func (h *Handler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id, organizationID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.MFA == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	ctx := r.Context()
	if err := h.refuseSharedCredentials(ctx, id, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	target, err := h.Repo.Get(ctx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.accounts().resetMFA(ctx, organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.tellCredentialChange(ctx, organizationID, target.Email, credentialFactorsReset, "")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "The user's multi-factor authentication has been reset. They can re-enroll at next sign-in.",
	})
}

func (h *Handler) listDeleted(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.OrganizationID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("organization scope required"))
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit := paging.Limit(r.URL.Query(), deletedLimit, deletedMaxLimit)
	out, next, err := h.Repo.ListDeleted(r.Context(), *p.OrganizationID, limit, after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(out, next))
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	id, organizationID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.accounts().restore(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
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
	id, organizationID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.accounts().purge(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.OrganizationID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("organization scope required"))
		return
	}
	filter, err := ParseListFilter(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit := paging.Limit(r.URL.Query(), listLimit, listMaxLimit)
	out, next, total, err := h.Repo.List(r.Context(), *p.OrganizationID, filter, limit, after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userPage{Result: paging.Page(out, next), Total: total})
}

// userPage is a page of the members list, with how many match in all.
type userPage struct {
	paging.Result[User]
	Total int `json:"total"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = organizationID
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	// The password is checked before anything is written, so a refused one
	// leaves no user row behind.
	var hash string
	if in.Password != "" {
		ph, err := h.hashNewPassword(r.Context(), organizationID, in.Email, in.Password)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		hash = ph
	}
	u, err := h.accounts().create(r.Context(), in, hash, nil, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, organizationID, err := h.memberID(r)
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
	member, err := h.Repo.Member(ctx, organizationID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u.Roles, u.AssignedRoles, u.MfaEnabled, u.GroupsCount = member.Roles, member.AssignedRoles, member.MfaEnabled, member.GroupsCount
	u.LastSeenAt, u.LastSeenIP, u.HomeOrganizationName = member.LastSeenAt, member.LastSeenIP, member.HomeOrganizationName
	if u.Suspension, err = h.Repo.SuspensionOf(ctx, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u.SeenBy(organizationID))
}

// me returns the caller's own user record, resolved from the principal rather
// than the path. It needs no organization.
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
	id, organizationID, err := h.actOnID(r)
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
	u, err := h.accounts().update(r.Context(), organizationID, id, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, organizationID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.accounts().softDelete(r.Context(), organizationID, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

type setPasswordInput struct {
	Password string `json:"password" validate:"required,max=256"` // length + rules: PasswordPolicy
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	id, organizationID, err := h.actOnID(r)
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
	if err := h.refuseSharedCredentials(r.Context(), id, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	hash, err := h.hashNewPassword(r.Context(), organizationID, target.Email, in.Password)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.accounts().setPassword(r.Context(), organizationID, id, hash, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.tellCredentialChange(r.Context(), organizationID, target.Email, credentialPasswordSet, "")
	w.WriteHeader(http.StatusNoContent)
}

// Check refuses a handler without the mailer that tells people of credential
// changes, what ends every way they are signed in, or what announces the
// sessions that ends, so bootstrap stops at start rather than serve without
// them.
func (h *Handler) Check() error {
	switch {
	case h.Mailer == nil:
		return errors.New("user: the user handler needs a mailer")
	case h.SignIns == nil:
		return errors.New("user: the user handler needs a sign-in ender")
	case h.Signals == nil:
		return errors.New("user: the user handler needs session signals")
	}
	return nil
}
