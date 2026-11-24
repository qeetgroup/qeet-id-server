package httpx

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Member returns the person the route parameter param names and the caller's
// organization: bad_request for a malformed id, not_found unless isMember says
// they belong to it.
func Member(r *http.Request, param string, isMember func(ctx context.Context, userID, organizationID uuid.UUID) (bool, error)) (userID, organizationID uuid.UUID, err error) {
	organizationID, err = RequireOrganization(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if userID, err = PathUUID(r, param, errs.ErrBadRequest.WithDetail("invalid "+param)); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	member, err := isMember(r.Context(), userID, organizationID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if !member {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return userID, organizationID, nil
}

// MemberToActOn is Member for a change to the person's ways of signing in:
// refused too unless ActOn lets the caller act on them.
func MemberToActOn(r *http.Request, param string, isMember func(ctx context.Context, userID, organizationID uuid.UUID) (bool, error),
	actOn func(ctx context.Context, caller *Principal, organizationID, targetID uuid.UUID) error) (userID, organizationID uuid.UUID, err error) {
	userID, organizationID, err = Member(r, param, isMember)
	if err == nil {
		err = ActOn(r, actOn, organizationID, userID)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, organizationID, nil
}

// ActOn refuses the caller of r changing targetID's account in organizationID when
// actOn (rbac.Repository.CheckActOn) says the target outranks them: only an
// owner changes an owner, and nobody someone holding a permission they don't.
// A nil actOn refuses, so a handler not wired for the check changes nothing.
func ActOn(r *http.Request, actOn func(ctx context.Context, caller *Principal, organizationID, targetID uuid.UUID) error, organizationID, targetID uuid.UUID) error {
	if actOn == nil {
		return errs.ErrNotImplemented
	}
	return actOn(r.Context(), PrincipalFromCtx(r.Context()), organizationID, targetID)
}
