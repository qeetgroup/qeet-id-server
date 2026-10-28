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

// ManagerOf returns the organisation that manages the accounts on email's
// domain: the one that verified the domain, or the closest domain above it.
// ok is false when none has. Other organisations don't create accounts there,
// and only the manager's single sign-on links them.
func ManagerOf(ctx context.Context, db dbgen.DBTX, email string) (tenantID uuid.UUID, ok bool, err error) {
	m, ok, err := ManagingDomain(ctx, db, email)
	return m.TenantID, ok, err
}

// ManagedDomain is the verified domain that decides for an address: its
// organisation and its switches.
type ManagedDomain struct {
	TenantID uuid.UUID
	SSO      bool // everyone on it signs in through the organisation's identity provider
	JIT      bool // single sign-on creates accounts on it
}

// ManagingDomain returns the domain ManagerOf takes the organisation from, with
// its switches; ok is false when no organisation manages email's domain.
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
	return ManagedDomain{TenantID: row.TenantID, SSO: row.SsoEnabled, JIT: row.JitEnabled}, true, nil
}

// CheckNewAccount refuses, with ErrUserDomainManaged, creating an account of
// tenantID on a domain another organisation manages. It reads every
// organisation's domains, so it runs on the pool before the creating
// transaction.
func CheckNewAccount(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, email string) error {
	manager, ok, err := ManagerOf(postgres.AcrossTenants(ctx), pool, email)
	if err != nil {
		return err
	}
	if ok && manager != tenantID {
		return errs.ErrUserDomainManaged
	}
	return nil
}
