//go:build integration

package gdpr

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestControlsSayWhenTheyStartedFailingAndWhoOwnsThem checks that a failing
// control carries a detail code, its parameters and a remedy, keeps the time
// it started failing across runs, and names the owner the organisation gave
// it, and that external audits are recorded, listed and removed.
func TestControlsSayWhenTheyStartedFailingAndWhoOwnsThem(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin, stranger := dbtest.User(t, tenant, tenant), dbtest.User(t, other, other)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant),
		(&Handler{Service: NewService(pool, 0), Evidence: NewEvidenceService(pool, audit.NewVerifier(pool), false)}).Mount)
	base := "/tenants/" + tenant.String() + "/compliance"
	run := func() EvidenceRun {
		t.Helper()
		var r EvidenceRun
		rec := dbtest.Do(t, h, http.MethodPost, base+"/soc2/evidence", nil)
		dbtest.Decode(t, rec, &r)
		if rec.Code != http.StatusCreated {
			t.Fatalf("generate: %d %s", rec.Code, rec.Body.String())
		}
		return r
	}
	control := func(r EvidenceRun, id string) ControlResult {
		t.Helper()
		for _, c := range r.Controls {
			if c.ID == id {
				return c
			}
		}
		t.Fatalf("run has no %s", id)
		return ControlResult{}
	}

	first := control(run(), "CC6.1-PWD-LEN")
	if first.Status != ControlFail || first.DetailCode != "password_length.too_short" || first.Remedy != "raise_password_min_length" ||
		first.Params["required"] != float64(12) || first.FailingSince == nil {
		t.Fatalf("a failing control: %+v, want its code, parameters, remedy and when it started failing", first)
	}
	time.Sleep(10 * time.Millisecond)

	if rec := dbtest.Do(t, h, http.MethodPut, base+"/controls/CC6.1-PWD-LEN/owner", map[string]any{"user_id": stranger.ID}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("another organisation's person as owner: %d, want 422", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, base+"/controls/NOPE/owner", map[string]any{"user_id": admin.ID}); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown control's owner: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, base+"/controls/CC6.1-PWD-LEN/owner", map[string]any{"user_id": admin.ID}); rec.Code != http.StatusNoContent {
		t.Fatalf("set the owner: %d %s", rec.Code, rec.Body.String())
	}
	second := control(run(), "CC6.1-PWD-LEN")
	if second.FailingSince == nil || !second.FailingSince.Equal(*first.FailingSince) {
		t.Errorf("failing since %v in the second run, want the first's %v", second.FailingSince, first.FailingSince)
	}
	if second.Owner == nil || second.Owner.UserID != admin.ID {
		t.Errorf("owner %+v, want the admin", second.Owner)
	}
	if pass := control(run(), "CC6.3-RBAC-ROLES"); pass.Status != ControlPass || pass.FailingSince != nil || pass.Remedy != "" || pass.DetailCode == "" {
		t.Errorf("a passing control: %+v", pass)
	}

	var recorded ExternalAudit
	rec := dbtest.Do(t, h, http.MethodPost, base+"/audits", map[string]any{
		"framework": "iso27001", "kind": "certificate", "body": "BSI", "scope": "Qeet ID production", "issued_on": "2026-03-01", "expires_on": "2029-02-28"})
	dbtest.Decode(t, rec, &recorded)
	if rec.Code != http.StatusCreated || recorded.Body != "BSI" || recorded.ExpiresOn == nil || *recorded.ExpiresOn != "2029-02-28" {
		t.Fatalf("record a certificate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base+"/audits", map[string]any{"framework": "soc2", "kind": "audit", "body": "", "issued_on": "March"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("an audit with no body or date: %d, want 422", rec.Code)
	}
	var list struct {
		Items []ExternalAudit `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/audits?framework=iso27001", nil), &list)
	if len(list.Items) != 1 || list.Items[0].ID != recorded.ID {
		t.Errorf("audits %+v, want the certificate", list.Items)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/audits/"+recorded.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete the certificate: %d", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action IN ('compliance.audit_recorded', 'compliance.audit_deleted', 'compliance.control_owner_set')`, tenant); n != 3 {
		t.Errorf("%d compliance changes audited, want 3", n)
	}
}
