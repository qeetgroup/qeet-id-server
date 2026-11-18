// Package provision is the one account-provisioning flow every federated sign-in (SAML, LDAP, OIDC
// single sign-on, social) runs: the account linked to the subject, else the one with the asserted
// address adopted under identitylink's checks, else a new one; then the link and, for a connection,
// ssosync. Each protocol keeps only its attribute mapping and its own errors.
package provision

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// Source is the identity provider a sign-in went through: one of the
// organization's connections, or one of its social providers.
type Source struct {
	OrganizationID uuid.UUID
	Provider       string    // the links' provider: "saml", "ldap", "oidc" or the social provider's name
	ConnectionID   uuid.UUID // the connection; uuid.Nil for a social provider
}

// Person is what the provider asserts about whom it signs in. EmailVerified is its own word on Email
// (nil for none); GroupsWithheld says it left groups out. LinkMetadata is what the link keeps of the
// profile (nil keeps what it holds), Profile what the attribute mapping made of it, for Flow.Store.
type Person struct {
	Subject        string
	Email          string
	EmailVerified  *bool
	Name           string
	Groups         []string
	GroupsWithheld bool
	LinkMetadata   []byte
	Profile        map[string]any
}

// Vouching is what the provider's word for the address is worth to the organization. Unproved, when
// set, is why it doesn't prove it: no account is adopted by it, and one created for it isn't marked
// verified. Adopt and Create are other reasons it may not adopt or create an account by it.
type Vouching struct {
	Unproved error
	Adopt    error
	Create   error
}

// Errors are a protocol's own errors for the refusals the flow makes. The
// three single sign-on ones are SingleSignOn's.
type Errors struct {
	NotHome            error // the account's home is another organization, or it is deleted
	EmailMissing       error // the provider names no address
	AccountUnverified  error // the account never proved owning the address
	AccountAdministers error // the account administers the organization
	DomainUnverified   error // the address isn't on a domain the organization manages
	EmailUnverified    error // the provider says it hasn't verified the address
	JITNotAllowed      error // the domain doesn't let single sign-on create accounts
}

// Recorder records refused sign-ins in the organization's audit trail.
// Satisfied by *auth.Service.
type Recorder interface {
	RecordSignInFailure(ctx context.Context, f auth.SignInFailure)
}

// Flow provisions the accounts one protocol's sign-ins name. Method ("saml", "ldap", "oidc",
// "social") is what the required Recorder records refusals under. Weigh weighs the provider's word
// for an address (nil: as SingleSignOn does); Store, when set, stores what else the connection maps
// onto the account, in the flow's transaction.
type Flow struct {
	Pool     *pgxpool.Pool
	Method   string
	Errors   Errors
	Recorder Recorder
	Weigh    func(ctx context.Context, src Source, p Person) (Vouching, error)
	Store    func(ctx context.Context, tx pgx.Tx, src Source, userID uuid.UUID, p Person) error
}

// errRefused refuses a sign-in for a reason the protocol names no error for,
// so a missing error never lets one through.
var errRefused = errs.ErrInternalServer.WithDetail("provision: refusal without an error")

func refusal(err error) error {
	if err == nil {
		return errRefused
	}
	return err
}

// Resolve returns the account p signs in through src: the one linked to p.Subject (only while this
// organization is its home), else the one with p.Email (adopted only if home here, it proved an address
// the provider proves and doesn't administer it), else a new one (Vouching permitting), then linked and,
// for a connection, kept in step. One transaction, so sign-ins can't duplicate rows; refusals recorded.
func (f *Flow) Resolve(ctx context.Context, src Source, p Person, actor audit.Actor) (userID uuid.UUID, err error) {
	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	// The record of a refusal names the account only once it is known to be
	// the organization's own: another organization's stays out of its trail.
	var named uuid.UUID
	defer func() {
		if err != nil {
			f.record(ctx, src, named, actor, err)
		}
	}()
	weigh := f.Weigh
	if weigh == nil {
		weigh = f.SingleSignOn
	}
	// Before the transaction: it reads every organization's domains.
	v, err := weigh(ctx, src, p)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := f.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	account, err := q.LinkedAccount(ctx, dbgen.LinkedAccountParams{
		OrganizationID: src.OrganizationID, Provider: src.Provider, Subject: p.Subject, ConnectionID: postgres.NullIfZero(src.ConnectionID),
	})
	switch {
	case err == nil:
		if err := f.requireHome(ctx, tx, account, src.OrganizationID); err != nil {
			return uuid.Nil, err
		}
	case errors.Is(err, pgx.ErrNoRows):
		if account, named, err = f.adoptOrCreate(ctx, tx, src, p, v); err != nil {
			return uuid.Nil, err
		}
	default:
		return uuid.Nil, err
	}
	if err := q.Link(ctx, dbgen.LinkParams{
		UserID: account, OrganizationID: src.OrganizationID, Provider: src.Provider, ConnectionID: postgres.NullIfZero(src.ConnectionID),
		Subject: p.Subject, Email: strutil.NilIfEmpty(p.Email), Metadata: p.LinkMetadata,
	}); err != nil {
		return uuid.Nil, err
	}
	// A connection is the organization's own directory: its sign-ins keep the
	// account's profile and groups in step, its address only where it proves it.
	if src.ConnectionID != uuid.Nil {
		if err := ssosync.Apply(ctx, tx, ssosync.SignIn{
			OrganizationID: src.OrganizationID, UserID: account, ConnectionID: src.ConnectionID, Provider: src.Provider,
			DisplayName: p.Name, Email: p.Email, EmailManaged: v.Unproved == nil,
			Groups: p.Groups, GroupsWithheld: p.GroupsWithheld, Actor: actor,
		}); err != nil {
			return uuid.Nil, err
		}
	}
	if f.Store != nil {
		if err := f.Store(ctx, tx, src, account, p); err != nil {
			return uuid.Nil, err
		}
	}
	return account, tx.Commit(ctx)
}

// adoptOrCreate returns the account with p's address, adopted, or a new one,
// under v, and the account a refusal may name: one at home in the
// organization.
func (f *Flow) adoptOrCreate(ctx context.Context, tx pgx.Tx, src Source, p Person, v Vouching) (account, named uuid.UUID, err error) {
	if p.Email == "" {
		return uuid.Nil, uuid.Nil, refusal(f.Errors.EmailMissing)
	}
	q := dbgen.New(tx)
	account, err = q.AccountByEmail(ctx, p.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		if v.Create != nil {
			return uuid.Nil, uuid.Nil, v.Create
		}
		account, err = q.InsertAccount(ctx, dbgen.InsertAccountParams{
			OrganizationID: &src.OrganizationID, Email: p.Email,
			Verified: v.Unproved == nil, DisplayName: strutil.NilIfEmpty(ssosync.DisplayName(p.Name)),
		})
		return account, uuid.Nil, err
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	// The provider must prove the address, or anyone who gets one to assert
	// someone's address inherits their account.
	if v.Unproved != nil {
		return uuid.Nil, uuid.Nil, v.Unproved
	}
	if v.Adopt != nil {
		return uuid.Nil, uuid.Nil, v.Adopt
	}
	// Addresses are unique across organizations, so the account may be
	// another organization's, or a guest's whose home is elsewhere.
	if err := f.requireHome(ctx, tx, account, src.OrganizationID); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	// The account must have proved the address itself, or a squatter who
	// registered it unverified keeps a working password on the adopted account.
	verified, err := identitylink.AddressVerified(ctx, tx, account)
	if err != nil {
		return uuid.Nil, account, err
	}
	if !verified {
		return uuid.Nil, account, refusal(f.Errors.AccountUnverified)
	}
	// An administrator keeps the credentials they have, or whoever can
	// configure a provider could assert an owner's address.
	admin, err := identitylink.Administers(ctx, tx, account, src.OrganizationID)
	if err != nil {
		return uuid.Nil, account, err
	}
	if admin {
		return uuid.Nil, account, refusal(f.Errors.AccountAdministers)
	}
	// The provider proved the address, so it is verified from now on.
	return account, account, identitylink.MarkAddressVerified(ctx, tx, account)
}

// requireHome refuses account unless organizationID is its home
// (identitylink.HomeIn).
func (f *Flow) requireHome(ctx context.Context, tx pgx.Tx, account, organizationID uuid.UUID) error {
	home, err := identitylink.HomeIn(ctx, tx, account, organizationID)
	if err != nil {
		return err
	}
	if !home {
		return refusal(f.Errors.NotHome)
	}
	return nil
}

// SingleSignOn weighs p's address as the organization's own identity provider speaks for it. Anyone who
// can configure a connection runs one, so it proves only addresses on domains the organization manages,
// and none it says it hasn't verified (one that doesn't say, as Microsoft Entra ID, is trusted there);
// it creates accounts only where the domain has just-in-time provisioning on.
func (f *Flow) SingleSignOn(ctx context.Context, src Source, p Person) (Vouching, error) {
	domain, managed, err := domainverify.ManagingDomain(postgres.AcrossOrganizations(ctx), f.Pool, strings.ToLower(strings.TrimSpace(p.Email)))
	if err != nil {
		return Vouching{}, err
	}
	switch {
	case !managed || domain.OrganizationID != src.OrganizationID:
		refused := refusal(f.Errors.DomainUnverified)
		return Vouching{Unproved: refused, Create: refused}, nil
	case p.EmailVerified != nil && !*p.EmailVerified:
		refused := refusal(f.Errors.EmailUnverified)
		return Vouching{Unproved: refused, Create: refused}, nil
	case !domain.JIT:
		return Vouching{Create: refusal(f.Errors.JITNotAllowed)}, nil
	}
	return Vouching{}, nil
}

// record records a refused sign-in through src, with the error code as its
// reason and the organization's own account it named, if any.
func (f *Flow) record(ctx context.Context, src Source, account uuid.UUID, actor audit.Actor, err error) {
	reason := errs.CodeInternal
	if e := errs.As(err); e != nil {
		reason = e.Code
	}
	meta := map[string]any{"provider": src.Provider}
	if src.ConnectionID != uuid.Nil {
		meta = map[string]any{"connection_id": src.ConnectionID.String()}
	}
	f.Recorder.RecordSignInFailure(ctx, auth.SignInFailure{
		OrganizationID: src.OrganizationID, UserID: account, Method: f.Method, Reason: reason,
		IP: actor.IP, UserAgent: actor.UserAgent, Metadata: meta,
	})
}
