// Package identitylink holds the checks every federated sign-in (provision's
// flow) runs on the account it would sign in, whether found by a linked
// identity or adopted by email. Emails are unique across organizations, so the
// account may belong elsewhere.
package identitylink

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// HomeIn reports whether organizationID is userID's home organization and the account isn't
// deleted. An organization's identity provider vouches only for its own
// accounts: if it also signed in its guests (a role there, home elsewhere), that
// organization's admin could assert a guest's address and switch the session
// into the guest's home. Callers must refuse the sign-in on false.
func HomeIn(ctx context.Context, q postgres.Querier, userID, organizationID uuid.UUID) (bool, error) {
	return dbgen.New(q).HomeIn(ctx, dbgen.HomeInParams{UserID: userID, OrganizationID: &organizationID})
}

// AddressVerified reports whether userID's email address is vouched for: the
// account proved owning it, or its organization's directory provisioned it
// (SCIM). Adopting an account by email needs it, or a squatter who registered
// the address unverified would keep a working password on the adopted account.
func AddressVerified(ctx context.Context, q postgres.Querier, userID uuid.UUID) (bool, error) {
	return dbgen.New(q).AddressVerified(ctx, userID)
}

// MarkAddressVerified records that userID's address is proved, when an
// organization's identity provider adopting the account vouched for it.
func MarkAddressVerified(ctx context.Context, q postgres.Querier, userID uuid.UUID) error {
	return dbgen.New(q).MarkAddressVerified(ctx, userID)
}

// memberPermissions are the reads an account may hold and still be a member:
// every other permission, including one added in a later release, makes it an
// administrator. Secrets' read reveals them, so it administers.
var memberPermissions = []string{
	"organization.read", "user.read", "role.read", "group.read", "connection.read", "apikey.read",
	"webhook.read", "billing.read", "policy.read", "audit.read", "analytics.read",
}

// MemberPermissions returns the permissions that don't administer an
// organization: single sign-on neither adopts an account holding any other nor
// gives one by group, and domain capture counts the same administrators.
func MemberPermissions() []string { return slices.Clone(memberPermissions) }

// Administers reports whether userID owns organizationID or holds a permission
// outside MemberPermissions there, directly or through a group. Single sign-on
// doesn't adopt such an account by its address, or whoever can configure a
// connection could assert an owner's address; it keeps its own credentials.
func Administers(ctx context.Context, q postgres.Querier, userID, organizationID uuid.UUID) (bool, error) {
	return dbgen.New(q).Administers(ctx, dbgen.AdministersParams{UserID: userID, OrganizationID: organizationID, MemberPermissions: memberPermissions})
}

// ActOn refuses caller acting on targetID's account in organizationID when the target
// outranks them. Satisfied by rbac.Repository.CheckActOn.
type ActOn func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error

// LinkedAdministrators returns the accounts that administer organizationID and are
// linked to its connection connID, or, when connID is uuid.Nil, to its social
// provider named provider: whatever that connection trusts can sign them in.
func LinkedAdministrators(ctx context.Context, q postgres.Querier, organizationID, connID uuid.UUID, provider string) ([]uuid.UUID, error) {
	return dbgen.New(q).LinkedAdministrators(ctx, dbgen.LinkedAdministratorsParams{
		OrganizationID: organizationID, ConnectionID: connID, Provider: provider, MemberPermissions: memberPermissions,
	})
}

// CheckTrustChange refuses caller changing what organizationID's connection (see
// LinkedAdministrators) trusts unless actOn lets them act on every
// administrator linked to it, as the changed connection could sign in as any
// of them. A caller who is no person (an admin-portal session) is refused
// whenever one is linked, as is every caller when actOn is nil.
func CheckTrustChange(ctx context.Context, q postgres.Querier, caller *httpx.Principal, actOn ActOn, organizationID, connID uuid.UUID, provider string) error {
	admins, err := LinkedAdministrators(ctx, q, organizationID, connID, provider)
	if err != nil || len(admins) == 0 {
		return err
	}
	if actOn == nil || caller == nil || caller.UserID == nil {
		return errs.ErrRBACTrustChangeOutranks
	}
	for _, id := range admins {
		if err := actOn(ctx, caller, organizationID, id); err != nil {
			if errors.Is(err, errs.ErrRBACTargetIsOwner) || errors.Is(err, errs.ErrRBACTargetOutranks) {
				return errs.ErrRBACTrustChangeOutranks
			}
			return err
		}
	}
	return nil
}
