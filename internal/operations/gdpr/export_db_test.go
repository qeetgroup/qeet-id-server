//go:build integration

package gdpr

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestExportPayloadExpires checks that a built export's payload is deleted
// after the retention window, or once its account is deleted for good,
// leaving the request expired and still naming the account, and that an
// export still within the window is kept.
func TestExportPayloadExpires(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	old, fresh, gone := account(t, organization), account(t, organization), account(t, organization)
	svc := testService(t, pool, 0)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	queue := func(userID uuid.UUID) uuid.UUID {
		var req ExportRequest
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": userID}), &req)
		return req.ID
	}
	oldReq, freshReq, goneReq := queue(old.ID), queue(fresh.ID), queue(gone.ID)
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.export_requests SET completed_at = $2 WHERE id = $1`,
		oldReq, time.Now().Add(-ExportRetention-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM account.users WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	n, err := ExpireExports(ctx, pool, ExportRetention)
	if err != nil || n != 2 {
		t.Fatalf("expired %d (%v), want 2", n, err)
	}
	get := func(id uuid.UUID) ExportRequest {
		var out ExportRequest
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/export/"+id.String(), nil), &out)
		return out
	}
	if got := get(goneReq); got.Status != "expired" || got.Payload != nil || got.UserID != gone.ID {
		t.Errorf("the export of a deleted account: %s for %s, want expired, without a payload, naming the account", got.Status, got.UserID)
	}
	if got := get(oldReq); got.Status != "expired" || got.Payload != nil {
		t.Errorf("an export past retention: %s with payload %v, want expired without one", got.Status, got.Payload != nil)
	}
	if got := get(freshReq); got.Status != "ready" || got.Payload == nil {
		t.Errorf("a recent export: %s, want ready with its payload", got.Status)
	}
}

// TestExportIsBuiltInTheBackground checks that an organization's export of a
// member is queued, built by the sweep without credentials, and readable only
// by that organization.
func TestExportIsBuiltInTheBackground(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	member := account(t, organization)
	svc := testService(t, dbtest.Pool(t), 0)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)

	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": member.ID})
	var req ExportRequest
	dbtest.Decode(t, rec, &req)
	if rec.Code != http.StatusAccepted || req.Status != "pending" {
		t.Fatalf("queue an export: %d %+v", rec.Code, req)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": account(t, other).ID}); rec.Code != http.StatusNotFound {
		t.Errorf("export another organization's member: %d, want 404", rec.Code)
	}
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	path := "/organizations/" + organization.String() + "/gdpr/export/" + req.ID.String()
	rec = dbtest.Do(t, asAdmin, http.MethodGet, path, nil)
	var ready ExportRequest
	dbtest.Decode(t, rec, &ready)
	profile, _ := ready.Payload["profile"].(map[string]any)
	sessions, _ := ready.Payload["sessions"].([]any)
	if ready.Status != "ready" || profile["email"] != member.Email || len(sessions) != 1 || rec.Header().Get("Content-Disposition") == "" {
		t.Errorf("built export: %s %v; want the member's data as a download", ready.Status, ready.Payload)
	}
	if strings.Contains(rec.Body.String(), "argon2") {
		t.Error("the export carries the password hash")
	}
	var list struct {
		Items []ExportRequest `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/export", nil), &list)
	if len(list.Items) != 1 || list.Items[0].Payload != nil {
		t.Errorf("exports listed %+v; want the one, without its payload", list.Items)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), requests(t, svc).Mount)
	if rec := dbtest.Do(t, asOther, http.MethodGet, "/organizations/"+other.String()+"/gdpr/export/"+req.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization reading the export: %d, want 404", rec.Code)
	}
}
