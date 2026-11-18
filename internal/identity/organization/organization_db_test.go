//go:build integration

package organization

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// announced records the session.revoked signals sent, by reason.
type announced struct {
	mu      sync.Mutex
	reasons []string
}

func (a *announced) enqueue(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ string, payload any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := payload.(map[string]any); ok {
		if reason, ok := p["reason"].(string); ok {
			a.reasons = append(a.reasons, reason)
		}
	}
	return nil
}

// newHandler returns the organization handler, issuing real token pairs, and
// what it announces.
func newHandler(t *testing.T) (*Handler, *auth.Service, *announced) {
	t.Helper()
	pool := dbtest.Pool(t)
	signals := &announced{}
	authSvc := authtest.New(t, pool)
	return &Handler{
		Repo:        NewRepository(pool, ""),
		Validate:    validator.New(validator.WithRequiredStructEnabled()),
		AuthService: authSvc,
		Signals:     sessionsignal.New(signals.enqueue),
		OwnerCheck:  rbac.NewRepository(pool).IsOwner,
	}, authSvc, signals
}

// verifiedAccount creates an account with a verified email and no
// organization.
func verifiedAccount(t *testing.T) dbtest.Account {
	t.Helper()
	a := dbtest.User(t, uuid.Nil)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	return a
}

// signedIn returns userID's principal in organization (uuid.Nil: none) with a live
// session that signed in an hour ago and ends in two.
func signedIn(t *testing.T, userID, organization uuid.UUID) *httpx.Principal {
	t.Helper()
	var organizationArg any
	if organization != uuid.Nil {
		organizationArg = organization
	}
	var session uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, organization_id, signed_in_at, expires_at)
		VALUES ($1, $2, NOW() - INTERVAL '1 hour', NOW() + INTERVAL '2 hours') RETURNING id
	`, userID, organizationArg).Scan(&session); err != nil {
		t.Fatal(err)
	}
	p := dbtest.Principal(userID, organization)
	p.SessionID = &session
	return p
}

// continues reports whether session continues from's sign-in: the same
// sign-in time, and an end no later.
func continues(t *testing.T, session, from uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `
		SELECT count(*) FROM auth.sessions s JOIN auth.sessions f ON f.id = $2
		WHERE s.id = $1 AND s.signed_in_at = f.signed_in_at AND s.expires_at <= f.expires_at
	`, session, from) == 1
}

// errorCode returns the error code of a JSON error answer.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	dbtest.Decode(t, rec, &body)
	return body.Error.Code
}

// ptr is a pointer to v.
