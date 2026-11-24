//go:build integration

package gdpr

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// erased reports whether the account's PII was redacted, its password and
// sessions gone.
func erased(t *testing.T, userID uuid.UUID) bool {
	t.Helper()
	var email, status string
	var passwords, live int
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT email, status,
		       (SELECT count(*) FROM auth.password_credentials WHERE user_id = u.id),
		       (SELECT count(*) FROM auth.sessions WHERE user_id = u.id AND revoked_at IS NULL)
		FROM account.users u WHERE id = $1
	`, userID).Scan(&email, &status, &passwords, &live); err != nil {
		t.Fatal(err)
	}
	return strings.HasSuffix(email, "@gdpr.invalid") && status == "deleted" && passwords == 0 && live == 0
}

// account returns a person at home in organization, with a password and a session.
func account(t *testing.T, organization uuid.UUID) dbtest.Account {
	t.Helper()
	a := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2)`, a.ID, organization); err != nil {
		t.Fatal(err)
	}
	return a
}

// requestStatus returns an erasure request's status.
func requestStatus(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT status FROM account.purge_requests WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// testService is a Service over pool whose erasure requests wait grace, and
// whose ended sessions are announced to no one.
func testService(t *testing.T, pool *pgxpool.Pool, grace time.Duration) *Service {
	t.Helper()
	signals := sessionsignal.New(func(context.Context, pgx.Tx, uuid.UUID, string, any) error { return nil })
	svc, err := NewService(pool, grace, signals)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// noPassword holds every account password-less, so deleting one needs only
// its session.
type noPassword struct{}

func (noPassword) ReauthPassword(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, true, nil
}

// handler is the handler for svc, with reauth and the outrank check bootstrap
// wires.
func handler(t *testing.T, svc *Service, reauth ReauthChecker) *Handler {
	t.Helper()
	h, err := NewHandler(svc, reauth, rbac.NewRepository(dbtest.Pool(t)).CheckActOn)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// requests is the data-request handler for svc, with the outrank check
// bootstrap wires.
func requests(t *testing.T, svc *Service) *Handler {
	t.Helper()
	return handler(t, svc, noPassword{})
}

// recorded checks that one action event was recorded in organization for request id,
// by actor (nil: the system) and naming userID.
func recorded(t *testing.T, organization, id uuid.UUID, action string, actor *uuid.UUID, userID uuid.UUID) {
	t.Helper()
	var n int
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT count(*) FROM audit.events
		WHERE organization_id = $1 AND resource_id = $2 AND action = $3
		  AND actor_user_id IS NOT DISTINCT FROM $4
		  AND actor_type = CASE WHEN $4::uuid IS NULL THEN 'system' ELSE 'user' END
		  AND metadata->>'user_id' = $5
	`, organization, id, action, actor, userID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d %s events for %s by %v about %s, want 1", n, action, id, actor, userID)
	}
}

// TestDataRequestsAreAudited checks that filing and cancelling an erasure and
// queueing an export are recorded as the administrator's, and the sweep's
// erasure, built export and failed export as the system's.
func TestDataRequestsAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	due, cancelled, exported := account(t, organization), account(t, organization), account(t, organization)
	svc := testService(t, pool, time.Nanosecond)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)

	file := func(path string, userID uuid.UUID) uuid.UUID {
		t.Helper()
		rec := dbtest.Do(t, asAdmin, http.MethodPost, path, map[string]any{"user_id": userID})
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body.String())
		}
		return out.ID
	}
	dueReq := file("/gdpr/purge", due.ID)
	recorded(t, organization, dueReq, "gdpr.erasure_requested", &admin.ID, due.ID)
	cancelledReq := file("/gdpr/purge", cancelled.ID)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelledReq.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d", rec.Code)
	}
	recorded(t, organization, cancelledReq, "gdpr.erasure_canceled", &admin.ID, cancelled.ID)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelledReq.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("cancel twice: %d, want 404", rec.Code)
	}
	recorded(t, organization, cancelledReq, "gdpr.erasure_canceled", &admin.ID, cancelled.ID)
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	recorded(t, organization, dueReq, "gdpr.erasure_completed", nil, due.ID)

	built := file("/gdpr/export", exported.ID)
	recorded(t, organization, built, "gdpr.export_requested", &admin.ID, exported.ID)
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	recorded(t, organization, built, "gdpr.export_completed", nil, exported.ID)

	failed := file("/gdpr/export", exported.ID)
	if err := svc.failExport(ctx, failed, organization, exported.ID, "not leased"); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.export_requests WHERE id = $1 AND status = 'pending'`, failed); n != 1 {
		t.Error("an export request another worker holds was marked failed")
	}
	if _, err := pool.Exec(ctx, `UPDATE account.export_requests SET lease_owner = $2, lease_until = NOW() + INTERVAL '1 minute' WHERE id = $1`, failed, svc.workerID); err != nil {
		t.Fatal(err)
	}
	if err := svc.failExport(ctx, failed, organization, exported.ID, "the build failed"); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.export_requests WHERE id = $1 AND status = 'failed' AND lease_owner IS NULL`, failed); n != 1 {
		t.Error("a leased export request wasn't marked failed")
	}
	recorded(t, organization, failed, "gdpr.export_failed", nil, exported.ID)
}

func TestMain(m *testing.M) { dbtest.Main(m) }
