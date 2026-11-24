//go:build integration

package gdpr

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAnErasureRequestNamesItsPersonUntilErased checks that an erasure
// request keeps the email and name of the person it was filed for, and its
// grace period, until the erasure runs, and then no longer.
func TestAnErasureRequestNamesItsPersonUntilErased(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	person := account(t, organization)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET display_name = 'Asha Iyer' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	svc := testService(t, dbtest.Pool(t), 30*24*time.Hour)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	var req Request
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, "/gdpr/purge", map[string]any{"user_id": person.ID}), &req)
	if req.SubjectEmail == nil || *req.SubjectEmail != person.Email || req.SubjectName == nil || *req.SubjectName != "Asha Iyer" ||
		req.Redacted || req.GraceDays != 30 {
		t.Fatalf("the filed request: %+v, want the person, a 30-day grace and nothing redacted", req)
	}
	due(t, req.ID)
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []Request `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/purge", nil), &list)
	if len(list.Items) != 1 || list.Items[0].SubjectEmail != nil || list.Items[0].SubjectName != nil || !list.Items[0].Redacted {
		t.Errorf("the erased request: %+v, want the person redacted", list.Items)
	}
}

// TestErasureWaitsForItsGracePeriod checks that an organization can order the
// erasure only of its own members, can cancel it while it waits, that an
// account awaiting erasure can't move organization, and that the sweep erases
// the account once the grace period ends.
func TestErasureWaitsForItsGracePeriod(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	due, waiting, outsider := account(t, organization), account(t, organization), account(t, other)
	svc := testService(t, pool, time.Nanosecond)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	waitingAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, testService(t, pool, 0)).Mount)

	order := func(h http.Handler, userID uuid.UUID) (int, Request) {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodPost, "/gdpr/purge", map[string]any{"user_id": userID, "reason": "asked by the person"})
		var req Request
		if rec.Code == http.StatusAccepted {
			dbtest.Decode(t, rec, &req)
		}
		return rec.Code, req
	}
	_, dueReq := order(asAdmin, due.ID)
	code, waitingReq := order(waitingAdmin, waiting.ID)
	if code != http.StatusAccepted || waitingReq.Status != "pending" || time.Until(waitingReq.GraceUntil) < 29*24*time.Hour || waitingReq.RequestedBy == nil || *waitingReq.RequestedBy != admin.ID {
		t.Errorf("order an erasure: %d %+v; want pending for 30 days, by the administrator", code, waitingReq)
	}
	if code, _ := order(asAdmin, outsider.ID); code != http.StatusNotFound {
		t.Errorf("erase another organization's member: %d, want 404", code)
	}
	_, cancelled := order(waitingAdmin, account(t, organization).ID)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelled.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("cancel: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelled.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("cancel twice: %d, want 404", rec.Code)
	}
	otherAdmin := dbtest.User(t, other, other)
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), requests(t, svc).Mount), http.MethodDelete, "/gdpr/purge/"+waitingReq.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization cancelling: %d, want 404", rec.Code)
	}

	_, err := pool.Exec(ctx, `UPDATE account.users SET organization_id = $2 WHERE id = $1`, waiting.ID, other)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("an account awaiting erasure moved organization: %v, want a foreign key violation", err)
	}
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !erased(t, due.ID) || requestStatus(t, dueReq.ID) != "completed" {
		t.Errorf("an account past its grace period wasn't erased (request %s)", requestStatus(t, dueReq.ID))
	}
	if erased(t, waiting.ID) || requestStatus(t, waitingReq.ID) != "pending" {
		t.Error("an account within its grace period was erased")
	}
	var list struct {
		Items []Request `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/purge", nil), &list)
	if len(list.Items) != 3 {
		t.Errorf("%d erasure requests listed, want 3", len(list.Items))
	}
}
