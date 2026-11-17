package domainverify

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ManagerOf returns the organization that manages the accounts on email's
// domain: the one that verified the domain, or the closest domain above it.
// ok is false when none has. Other organizations don't create accounts there,
// and only the manager's single sign-on links them.
func ManagerOf(ctx context.Context, db dbgen.DBTX, email string) (organizationID uuid.UUID, ok bool, err error) {
	m, ok, err := ManagingDomain(ctx, db, email)
	return m.OrganizationID, ok, err
}

// ManagedDomain is the verified domain that decides for an address: its
// organization and its switches.
type ManagedDomain struct {
	OrganizationID uuid.UUID
	SSO            bool // everyone on it signs in through the organization's identity provider
	JIT            bool // single sign-on creates accounts on it
}

// ManagingDomain returns the domain ManagerOf takes the organization from, with
// its switches; ok is false when no organization manages email's domain.
func ManagingDomain(ctx context.Context, db dbgen.DBTX, email string) (m ManagedDomain, ok bool, err error) {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return m, false, nil
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	if domain == "" {
		return m, false, nil
	}
	row, err := dbgen.New(db).EmailDomainManager(ctx, domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	return ManagedDomain{OrganizationID: row.OrganizationID, SSO: row.SsoEnabled, JIT: row.JitEnabled}, true, nil
}

// CheckNewAccount refuses, with ErrUserDomainManaged, creating an account of
// organizationID on a domain another organization manages. It reads every
// organization's domains, so it runs on the pool before the creating
// transaction.
func CheckNewAccount(ctx context.Context, pool *pgxpool.Pool, organizationID uuid.UUID, email string) error {
	manager, ok, err := ManagerOf(postgres.AcrossOrganizations(ctx), pool, email)
	if err != nil {
		return err
	}
	if ok && manager != organizationID {
		return errs.ErrUserDomainManaged
	}
	return nil
}
