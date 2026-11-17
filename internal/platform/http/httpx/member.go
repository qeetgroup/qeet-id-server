package httpx

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Member returns the person the route parameter param names and the caller's
// organisation: bad_request for a malformed id, not_found unless isMember says
// they belong to it.
func Member(r *http.Request, param string, isMember func(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)) (userID, tenantID uuid.UUID, err error) {
	tenantID, err = RequireTenant(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	userID, err = uuid.Parse(chi.URLParam(r, param))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid " + param)
	}
	member, err := isMember(r.Context(), userID, tenantID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if !member {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return userID, tenantID, nil
}

// MemberToActOn is Member for a change to the person's ways of signing in:
// refused too unless ActOn lets the caller act on them.
func MemberToActOn(r *http.Request, param string, isMember func(ctx context.Context, userID, tenantID uuid.UUID) (bool, error),
	actOn func(ctx context.Context, caller *Principal, tenantID, targetID uuid.UUID) error) (userID, tenantID uuid.UUID, err error) {
	userID, tenantID, err = Member(r, param, isMember)
	if err == nil {
		err = ActOn(r, actOn, tenantID, userID)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, tenantID, nil
}

// ActOn refuses the caller of r changing targetID's account in tenantID when
// actOn (rbac.Repository.CheckActOn) says the target outranks them: only an
// owner changes an owner, and nobody someone holding a permission they don't.
// A nil actOn refuses, so a handler not wired for the check changes nothing.
func ActOn(r *http.Request, actOn func(ctx context.Context, caller *Principal, tenantID, targetID uuid.UUID) error, tenantID, targetID uuid.UUID) error {
	if actOn == nil {
		return errs.ErrNotImplemented
	}
	return actOn(r.Context(), PrincipalFromCtx(r.Context()), tenantID, targetID)
}
