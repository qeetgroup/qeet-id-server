//go:build integration

package gdpr

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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
		FROM "user".users u WHERE id = $1
	`, userID).Scan(&email, &status, &passwords, &live); err != nil {
		t.Fatal(err)
	}
	return strings.HasSuffix(email, "@gdpr.invalid") && status == "deleted" && passwords == 0 && live == 0
}

// account returns a person at home in tenant, with a password and a session.
func account(t *testing.T, tenant uuid.UUID) dbtest.Account {
	t.Helper()
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2)`, a.ID, tenant); err != nil {
		t.Fatal(err)
	}
	return a
}

// requestStatus returns an erasure request's status.
func requestStatus(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT status FROM "user".purge_requests WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// TestErasureWaitsForItsGracePeriod checks that an organisation can order the
// erasure only of its own members, can cancel it while it waits, that an
// account awaiting erasure can't move organisation, and that the sweep erases
// the account once the grace period ends.
func TestErasureWaitsForItsGracePeriod(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	due, waiting, outsider := account(t, tenant), account(t, tenant), account(t, other)
	svc := NewService(pool, time.Nanosecond)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	waitingAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: NewService(pool, 0)}).Mount)

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
		t.Errorf("erase another organisation's member: %d, want 404", code)
	}
	_, cancelled := order(waitingAdmin, account(t, tenant).ID)
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelled.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("cancel: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/gdpr/purge/"+cancelled.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("cancel twice: %d, want 404", rec.Code)
	}
	otherAdmin := dbtest.User(t, other, other)
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount), http.MethodDelete, "/gdpr/purge/"+waitingReq.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation cancelling: %d, want 404", rec.Code)
	}

	_, err := pool.Exec(ctx, `UPDATE "user".users SET tenant_id = $2 WHERE id = $1`, waiting.ID, other)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("an account awaiting erasure moved organisation: %v, want a foreign key violation", err)
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
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/gdpr/purge", nil), &list)
	if len(list.Items) != 3 {
		t.Errorf("%d erasure requests listed, want 3", len(list.Items))
	}
}

// TestExportIsBuiltInTheBackground checks that an organisation's export of a
// member is queued, built by the sweep without credentials, and readable only
// by that organisation.
func TestExportIsBuiltInTheBackground(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	member := account(t, tenant)
	svc := NewService(dbtest.Pool(t), 0)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)

	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": member.ID})
	var req ExportRequest
	dbtest.Decode(t, rec, &req)
	if rec.Code != http.StatusAccepted || req.Status != "pending" {
		t.Fatalf("queue an export: %d %+v", rec.Code, req)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": account(t, other).ID}); rec.Code != http.StatusNotFound {
		t.Errorf("export another organisation's member: %d, want 404", rec.Code)
	}
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	path := "/tenants/" + tenant.String() + "/gdpr/export/" + req.ID.String()
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
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/gdpr/export", nil), &list)
	if len(list.Items) != 1 || list.Items[0].Payload != nil {
		t.Errorf("exports listed %+v; want the one, without its payload", list.Items)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	if rec := dbtest.Do(t, asOther, http.MethodGet, "/tenants/"+other.String()+"/gdpr/export/"+req.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation reading the export: %d, want 404", rec.Code)
	}
}

// passwordCheck re-verifies the account's password as want.
type passwordCheck struct{ want string }

func (c passwordCheck) ReauthPassword(_ context.Context, _ uuid.UUID, plain string) (bool, bool, error) {
	return true, plain == c.want, nil
}

// TestDeleteOwnAccount checks that a person deletes their own account at once,
// only with their password when they have one.
func TestDeleteOwnAccount(t *testing.T) {
	tenant := dbtest.Tenant(t)
	a := account(t, tenant)
	h := dbtest.Serve(dbtest.Principal(a.ID, tenant), (&Handler{Service: NewService(dbtest.Pool(t), 0), Reauth: passwordCheck{"Kx7mQ2vLp9Wz"}}).Mount)
	if rec := dbtest.Do(t, h, http.MethodPost, "/account/delete", map[string]string{"password": "wrong"}); rec.Code != http.StatusBadRequest || erased(t, a.ID) {
		t.Errorf("delete with the wrong password: %d", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/account/delete", map[string]string{"password": "Kx7mQ2vLp9Wz"}); rec.Code != http.StatusNoContent || !erased(t, a.ID) {
		t.Errorf("delete with the password: %d, erased %v", rec.Code, erased(t, a.ID))
	}
}

// TestComplianceEvidence checks that evidence is generated from the
// organisation's live state for each framework, stored with its controls, and
// readable only by that organisation.
func TestComplianceEvidence(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := &Handler{Service: NewService(pool, 0), Evidence: NewEvidenceService(pool, audit.NewVerifier(pool), true)}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	base := "/tenants/" + tenant.String() + "/compliance/"

	var soc2 EvidenceRun
	for _, framework := range []string{"soc2", "iso27001"} {
		rec := dbtest.Do(t, asAdmin, http.MethodPost, base+framework+"/evidence", nil)
		var run EvidenceRun
		dbtest.Decode(t, rec, &run)
		if rec.Code != http.StatusCreated || len(run.Controls) == 0 || run.PassCount+run.FailCount+run.NACount != len(run.Controls) || run.GeneratedBy == nil {
			t.Fatalf("%s evidence: %d %+v", framework, rec.Code, run)
		}
		for _, c := range run.Controls {
			if c.Detail == "" || (c.Status != ControlPass && c.Status != ControlFail && c.Status != ControlNA) {
				t.Errorf("%s control %s: %q %q", framework, c.ID, c.Status, c.Detail)
			}
		}
		if framework == "soc2" {
			soc2 = run
		}
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, base+"hipaa/evidence", nil); rec.Code/100 != 4 {
		t.Errorf("an unknown framework: %d, want refused", rec.Code)
	}
	var list struct {
		Items []EvidenceRun `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, base+"soc2/evidence", nil), &list)
	if len(list.Items) != 1 || list.Items[0].ID != soc2.ID || list.Items[0].Controls != nil {
		t.Errorf("soc2 runs %+v; want the one, without controls", list.Items)
	}
	var stored EvidenceRun
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, base+"evidence/"+soc2.ID.String(), nil), &stored)
	if len(stored.Controls) != len(soc2.Controls) {
		t.Errorf("stored run has %d controls, want %d", len(stored.Controls), len(soc2.Controls))
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	if rec := dbtest.Do(t, asOther, http.MethodGet, "/tenants/"+other.String()+"/compliance/evidence/"+soc2.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation reading the evidence: %d, want 404", rec.Code)
	}
}
