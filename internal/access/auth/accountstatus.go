package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// refuseInactiveAccount refuses, with ErrAuthAccountInactive, a sign-in to an
// account that is deleted or neither active nor invited, and audits it. Every
// sign-in path calls it before issuing a session, so suspending an account
// closes every way in.
func (s *Service) refuseInactiveAccount(ctx context.Context, userID, organizationID uuid.UUID, method, ip, ua string) error {
	st, err := s.q.AccountStanding(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrAuthAccountInactive
	}
	if err != nil {
		return err
	}
	if !st.Deleted && (st.Status == "active" || st.Status == "invited") {
		return nil
	}
	_ = audit.RecordAlone(ctx, s.pool, asUser(userID, ip, ua).EventIn(orNil(organizationID), "auth.sign_in_refused", "user", userID,
		map[string]any{"reason": "account_inactive", "status": st.Status, "deleted": st.Deleted, "method": method}))
	return errs.ErrAuthAccountInactive
}

// refuseInactiveOrganization refuses, with ErrAuthOrganizationInactive, a session for an
// organization that is suspended or deleted (uuid.Nil: organization-less, nothing
// to check). Every sign-in and switch ends in the issuing step that asks it.
func (s *Service) refuseInactiveOrganization(ctx context.Context, organizationID uuid.UUID) error {
	if organizationID == uuid.Nil {
		return nil
	}
	active, err := s.q.OrganizationActive(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
		return ErrOrganizationInactive
	}
	return err
}

// refuseSignIn refuses a session for an inactive account or organization, or
// from an address the organization's rules refuse. Every caller of issuePairTx
// runs it before beginning the transaction: each check reads, and records a
// refusal, on the pool.
func (s *Service) refuseSignIn(ctx context.Context, userID, organizationID uuid.UUID, method, ip, ua string) error {
	if err := s.refuseInactiveAccount(ctx, userID, organizationID, method, ip, ua); err != nil {
		return err
	}
	if err := s.refuseInactiveOrganization(ctx, organizationID); err != nil {
		return err
	}
	return s.checkAddress(ctx, organizationID, userID, ip, method)
}

// CheckSignInAccount is refuseInactiveAccount for a sign-in that hands out
// something before the session — a social provider's one-time code, which
// would otherwise be issued to a suspended account and refused only at the
// exchange.
func (s *Service) CheckSignInAccount(ctx context.Context, userID, organizationID uuid.UUID, method, ip, ua string) error {
	return s.refuseInactiveAccount(ctx, userID, organizationID, method, ip, ua)
}
