//go:build integration

package siem

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestDestinationsCanBeTested checks that a test event reaches a saved or an
// unsaved destination with its credential, reports a refusal without marking
// the destination failing, stays in the organization, and is audited.
func TestDestinationsCanBeTested(t *testing.T) {
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(pool, egress.DevelopmentPolicy())
	svc.SetCipher(box)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	sink := newCollector(t)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/log-sinks"
	var saved Sink
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base, map[string]string{"type": "http", "endpoint": sink.URL + "/saved", "token": "tok-saved"}), &saved)
	var result TestResult

	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base+"/"+saved.ID.String()+"/test", nil), &result)
	if got := sink.received("/saved"); !result.Delivered || result.Status != http.StatusOK || len(got) != 1 || !strings.Contains(got[0], "tok-saved") || !strings.Contains(got[0], `"siem.test"`) {
		t.Errorf("test a saved destination: %+v, received %v; want one test event with its token", result, got)
	}
	sink.mu.Lock()
	sink.status = http.StatusServiceUnavailable
	sink.mu.Unlock()
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base+"/"+saved.ID.String()+"/test", nil), &result)
	if result.Delivered || result.Status != http.StatusServiceUnavailable || result.Error == "" {
		t.Errorf("a refusing destination: %+v, want not delivered with its status", result)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.log_sinks WHERE id = $1 AND last_error = '' AND failures = 0`, saved.ID); n != 1 {
		t.Error("a test marked the destination failing")
	}
	sink.mu.Lock()
	sink.status = http.StatusOK
	sink.mu.Unlock()

	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base+"/test", map[string]string{"type": "splunk_hec", "endpoint": sink.URL + "/unsaved", "token": "tok-new"}), &result)
	if got := sink.received("/unsaved"); !result.Delivered || len(got) != 1 || !strings.Contains(got[0], "tok-new") {
		t.Errorf("test an unsaved destination: %+v, received %v", result, got)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base+"/test", map[string]string{"type": "syslog", "endpoint": sink.URL}); rec.Code/100 != 4 {
		t.Errorf("an unknown type: %d, want refused", rec.Code)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/organizations/"+other.String()+"/log-sinks/"+saved.ID.String()+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization testing this destination: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'siem.sink_tested'`, organization); n != 3 {
		t.Errorf("%d tests audited, want 3", n)
	}
}
