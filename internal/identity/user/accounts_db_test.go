//go:build integration

package user

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// errSignOutFailed is the failure of failingSignIns.
var errSignOutFailed = errors.New("sign-out failed")

// failingSignIns is a signInEnder that ends the person's sessions in tx and
// then fails, as a later step of a sign-out the database refuses would.
type failingSignIns struct{}

// EndAllSignIns ends userID's sessions in tx, then fails.
func (failingSignIns) EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error) {
	if _, err := (endSessions{}).EndAllSignIns(ctx, tx, userID, reason); err != nil {
		return SignInsEnded{}, err
	}
	return SignInsEnded{}, errSignOutFailed
}

// fullSeats is a RoleGranter whose role never fits in the seats left.
type fullSeats struct{}

// CheckGrant allows any role.
func (fullSeats) CheckGrant(*http.Request, uuid.UUID, uuid.UUID) (int, error) { return 0, nil }

// Assign refuses the seat.
func (fullSeats) Assign(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID, *uuid.UUID, int) error {
	return errs.ErrPlanLimit
}

// TestAccountChangesCommitWithTheirAuditRow checks that an administrator's
// change to an account commits in one transaction with its audit row,
// recorded with the actor's address, browser and request, and that when a
// later step fails the change and its row roll back together.
func TestAccountChangesCommitWithTheirAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user", IP: "198.51.100.7", UserAgent: "accounts-test", RequestID: "req-accounts"}
	byActor := func(action string, resource uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $4
			  AND host(ip) = $5 AND user_agent = $6 AND request_id = $7`,
			organization, action, resource, admin.ID, actor.IP, actor.UserAgent, actor.RequestID)
	}
	accounts := testHandler(t, nil).accounts()
	failing := accounts
	failing.signIns, failing.roles = failingSignIns{}, fullSeats{}

	t.Run("create", func(t *testing.T) {
		u, err := accounts.create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("made") + "@example.test"}, "", nil, actor)
		if err != nil || byActor("user.created", u.ID) != 1 {
			t.Fatalf("create: %v, %d user.created rows as the actor's; want 1", err, byActor("user.created", u.ID))
		}
		refused := dbtest.Unique("refused") + "@example.test"
		if _, err := failing.create(ctx, CreateInput{OrganizationID: organization, Email: refused}, "", &importRole{ID: uuid.New()}, actor); !errors.Is(err, errs.ErrPlanLimit) {
			t.Fatalf("create with no seat for its role: %v, want %v", err, errs.ErrPlanLimit)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, refused); n != 0 {
			t.Errorf("a create whose role was refused left %d accounts, want none", n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'user.created' AND metadata->>'email' = $2`, organization, refused); n != 0 {
			t.Errorf("a create whose role was refused left %d user.created rows, want none", n)
		}
	})

	t.Run("delete", func(t *testing.T) {
		target := dbtest.User(t, organization, organization)
		session(t, target.ID, organization, "")
		deleted := func() int {
			return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND deleted_at IS NOT NULL`, target.ID)
		}
		if _, err := failing.softDelete(ctx, organization, target.ID, actor); !errors.Is(err, errSignOutFailed) {
			t.Fatalf("delete whose sign-out fails: %v, want %v", err, errSignOutFailed)
		}
		if deleted() != 0 || liveSessions(t, target.ID) != 1 || audited(t, organization, "user.deleted", target.ID) != 0 {
			t.Errorf("a failed delete left the account deleted %d, %d live sessions, %d user.deleted rows; want 0, 1, 0",
				deleted(), liveSessions(t, target.ID), audited(t, organization, "user.deleted", target.ID))
		}
		if _, err := accounts.softDelete(ctx, organization, target.ID, actor); err != nil {
			t.Fatal(err)
		}
		if deleted() != 1 || liveSessions(t, target.ID) != 0 || byActor("user.deleted", target.ID) != 1 {
			t.Errorf("delete: deleted %d, %d live sessions, %d user.deleted rows as the actor's; want 1, 0, 1",
				deleted(), liveSessions(t, target.ID), byActor("user.deleted", target.ID))
		}
	})

	t.Run("set password", func(t *testing.T) {
		target := dbtest.User(t, organization, organization)
		session(t, target.ID, organization, "")
		stored := func() int {
			return dbtest.Count(t, `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`, target.ID)
		}
		if err := failing.setPassword(ctx, organization, target.ID, "hash", actor); !errors.Is(err, errSignOutFailed) {
			t.Fatalf("set password whose sign-out fails: %v, want %v", err, errSignOutFailed)
		}
		if stored() != 0 || liveSessions(t, target.ID) != 1 || audited(t, organization, "user.password_set", target.ID) != 0 {
			t.Errorf("a failed password set left %d passwords, %d live sessions, %d user.password_set rows; want 0, 1, 0",
				stored(), liveSessions(t, target.ID), audited(t, organization, "user.password_set", target.ID))
		}
		if err := accounts.setPassword(ctx, organization, target.ID, "hash", actor); err != nil {
			t.Fatal(err)
		}
		if stored() != 1 || liveSessions(t, target.ID) != 0 || byActor("user.password_set", target.ID) != 1 {
			t.Errorf("set password: %d passwords, %d live sessions, %d user.password_set rows as the actor's; want 1, 0, 1",
				stored(), liveSessions(t, target.ID), byActor("user.password_set", target.ID))
		}
	})

	t.Run("suspend", func(t *testing.T) {
		target := dbtest.User(t, organization, organization)
		session(t, target.ID, organization, "")
		suspended := "suspended"
		status := func() string {
			var s string
			if err := dbtest.Pool(t).QueryRow(ctx, `SELECT status FROM account.users WHERE id = $1`, target.ID).Scan(&s); err != nil {
				t.Fatal(err)
			}
			return s
		}
		if _, err := failing.update(ctx, organization, target.ID, UpdateInput{Status: &suspended}, actor); !errors.Is(err, errSignOutFailed) {
			t.Fatalf("suspend whose sign-out fails: %v, want %v", err, errSignOutFailed)
		}
		if status() != "active" || liveSessions(t, target.ID) != 1 || audited(t, organization, "user.suspended", target.ID) != 0 {
			t.Errorf("a failed suspension left status %s, %d live sessions, %d user.suspended rows; want active, 1, 0",
				status(), liveSessions(t, target.ID), audited(t, organization, "user.suspended", target.ID))
		}
		if _, err := accounts.update(ctx, organization, target.ID, UpdateInput{Status: &suspended}, actor); err != nil {
			t.Fatal(err)
		}
		if status() != "suspended" || liveSessions(t, target.ID) != 0 || byActor("user.suspended", target.ID) != 1 {
			t.Errorf("suspend: status %s, %d live sessions, %d user.suspended rows as the actor's; want suspended, 0, 1",
				status(), liveSessions(t, target.ID), byActor("user.suspended", target.ID))
		}
		if _, err := accounts.reactivate(ctx, organization, admin.ID, actor); !errors.Is(err, errs.ErrForbidden) {
			t.Errorf("reactivating one's own account: %v, want %v", err, errs.ErrForbidden)
		}
		if _, err := accounts.reactivate(ctx, organization, target.ID, actor); err != nil || status() != "active" || byActor("user.reactivated", target.ID) != 1 {
			t.Errorf("reactivate: %v, status %s, %d user.reactivated rows as the actor's; want active and 1", err, status(), byActor("user.reactivated", target.ID))
		}
	})
}

// TestNoAccountsOnAnotherOrganizationsDomain checks that an organization
// creates no account, alone or in bulk, on a domain another organization has
// verified or below it, while its own domains and unclaimed ones stay open.
func TestNoAccountsOnAnotherOrganizationsDomain(t *testing.T) {
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	own, theirs := dbtest.Domain(t, organization), dbtest.Domain(t, other)
	admin := dbtest.User(t, organization, organization)
	h := &Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)

	for _, email := range []string{
		dbtest.Unique("a") + "@" + theirs,
		dbtest.Unique("a") + "@eu." + theirs,
		dbtest.Unique("a") + "@" + strings.ToUpper(theirs),
	} {
		if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": email}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeUserDomainManaged) {
			t.Errorf("create %s: %d %s, want 409 %s", email, rec.Code, rec.Body.String(), errs.CodeUserDomainManaged)
		}
	}
	for _, email := range []string{
		dbtest.Unique("a") + "@" + own,
		dbtest.Unique("a") + "@eu." + own,
		dbtest.Unique("a") + "@example.test",
	} {
		if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": email}); rec.Code != http.StatusCreated {
			t.Errorf("create %s: %d %s, want 201", email, rec.Code, rec.Body.String())
		}
	}

	claimed, open := dbtest.Unique("bulk")+"@"+theirs, dbtest.Unique("bulk")+"@"+own
	rec := dbtest.Do(t, as, http.MethodPost, "/users/bulk", map[string]any{"users": []map[string]any{{"email": claimed}, {"email": open}}})
	var res BulkImportResult
	dbtest.Decode(t, rec, &res)
	want := BulkImportError{Line: 1, Email: claimed, Code: errs.CodeUserDomainManaged, Field: "email", Message: errs.ErrUserDomainManaged.Message}
	if rec.Code != http.StatusOK || res.Succeeded != 1 || len(res.Errors) != 1 || res.Errors[0] != want {
		t.Errorf("bulk create: %d %+v, want the claimed row refused as %+v", rec.Code, res, want)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE organization_id = $1 AND lower(email) LIKE '%' || $2`, organization, theirs); n != 0 {
		t.Errorf("%d accounts created on another organization's domain", n)
	}
}
