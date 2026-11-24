//go:build integration

package compliance

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestComplianceEvidence checks that evidence is generated from the
// organization's live state for each framework, stored with its controls, and
// readable only by that organization.
func TestComplianceEvidence(t *testing.T) {
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := &Handler{Evidence: NewEvidenceService(pool, audit.NewVerifier(pool, nil), true)}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	base := "/organizations/" + organization.String() + "/compliance/"

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
	if rec := dbtest.Do(t, asOther, http.MethodGet, "/organizations/"+other.String()+"/compliance/evidence/"+soc2.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization reading the evidence: %d, want 404", rec.Code)
	}
}
