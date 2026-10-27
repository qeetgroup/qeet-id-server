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
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return uuid.Nil, false, nil
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	if domain == "" {
		return uuid.Nil, false, nil
	}
	tenantID, err = dbgen.New(db).EmailDomainManager(ctx, domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return tenantID, err == nil, err
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
