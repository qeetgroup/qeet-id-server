//go:build integration

package user

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// endSessions is a signInEnder that ends the person's sessions, the part of
// ending every sign-in that this package can see.
type endSessions struct{}

// clearTOTP is an mfaResetter that removes the person's authenticator app.
type clearTOTP struct{}

// testHandler returns the user routes with a password policy that accepts
// anything, sign-ins ended by endSessions, second factors reset by clearTOTP
// and mail kept in mailbox.
func testHandler(t *testing.T, mailbox *dbtest.Mailbox) *Handler {
	t.Helper()
	return &Handler{
		Repo:           NewRepository(dbtest.Pool(t)),
		Validate:       jsonNamedValidator(),
		PasswordPolicy: func(context.Context, uuid.UUID, string, string) error { return nil },
		MFA:            clearTOTP{},
		SignIns:        endSessions{},
		Mailer:         mailbox,
		ActOnCheck:     rbac.NewRepository(dbtest.Pool(t)).CheckActOn,
	}
}

// exec runs a statement that sets up a test, failing t if it errors.
func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), sql, args...); err != nil {
		t.Fatalf("set up: %v\n%s", err, sql)
	}
}

// session gives the user a live session in organization (nil: none) from ip ("":
// unknown) and returns its id.
func session(t *testing.T, userID uuid.UUID, organization any, ip string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, organization_id, ip) VALUES ($1, $2, NULLIF($3, '')::inet) RETURNING id
	`, userID, organization, ip).Scan(&id); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return id
}

// liveSessions counts the user's sessions that have not been revoked.
func liveSessions(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID)
}

// audited counts the organization's audit events of action about resource.
func audited(t *testing.T, organization uuid.UUID, action string, resource uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3`, organization, action, resource)
}

func uuidCompare(a, b uuid.UUID) int {
	return slices.Compare(a[:], b[:])
}

// TestGuestOrganizationsDontSeeHomeMetadata checks that the metadata a
// person's home organization keeps on them is shown to it, and not to an
// organization they are only a guest in, whether read alone or in its list.
func TestGuestOrganizationsDontSeeHomeMetadata(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	home, guestOf := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, home, home, guestOf)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET metadata = '{"salary_band":"L7"}' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}
	seen := func(organization uuid.UUID) (single, listed string) {
		t.Helper()
		as := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), h.Mount)
		single = dbtest.Do(t, as, http.MethodGet, "/users/"+person.ID.String(), nil).Body.String()
		listed = dbtest.Do(t, as, http.MethodGet, "/users?limit=200", nil).Body.String()
		return single, listed
	}
	if single, listed := seen(home); !strings.Contains(single, "salary_band") || !strings.Contains(listed, "salary_band") {
		t.Errorf("the home organization: %s / %s; want the metadata", single, listed)
	}
	if single, listed := seen(guestOf); strings.Contains(single, "salary_band") || strings.Contains(listed, "salary_band") || !strings.Contains(listed, person.Email) {
		t.Errorf("a guest organization: %s / %s; want the person without the metadata", single, listed)
	}
}

// EndAllSignIns ends userID's live sessions in tx and counts them.
func (endSessions) EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, _ string) (SignInsEnded, error) {
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	return SignInsEnded{Sessions: int64(len(ended))}, err
}

// ResetForUser deletes userID's authenticator app in tx and counts it.
func (clearTOTP) ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id = $1`, userID)
	return map[string]int64{"totp": tag.RowsAffected()}, err
}
