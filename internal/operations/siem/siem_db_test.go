//go:build integration

package siem

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// collector is a fake log endpoint: it keeps each request's path, credential
// header and body, and answers status.
type collector struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	requests []string
}

// newCollector starts a collector answering 200 until t ends.
func newCollector(t *testing.T) *collector {
	c := &collector{status: http.StatusOK}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, r.URL.Path+" "+r.Header.Get("Authorization")+r.Header.Get("DD-API-KEY")+" "+string(body))
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.Close)
	return c
}

// received returns the requests made to path.
func (c *collector) received(path string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.requests {
		if strings.HasPrefix(r, path+" ") {
			out = append(out, r)
		}
	}
	return out
}

// TestSinksForwardTheOrganizationsEvents checks that each kind of log sink
// receives its organization's new audit events, with its credential, once,
// and no other organization's; that a failing endpoint is recorded; that a
// disabled sink receives nothing; and that sinks are managed per organization.
func TestSinksForwardTheOrganizationsEvents(t *testing.T) {
	ctx := dbtest.Context(t)
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
	base := "/tenants/" + organization.String() + "/log-sinks"

	ids := map[string]string{}
	for typ, path := range map[string]string{"http": "/http", "splunk_hec": "/splunk", "datadog": "/dd"} {
		rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"type": typ, "endpoint": sink.URL + path, "token": "tok-" + typ})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s sink: %d %s", typ, rec.Code, rec.Body.String())
		}
		var created Sink
		dbtest.Decode(t, rec, &created)
		ids[path] = created.ID.String()
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"type": "syslog", "endpoint": sink.URL}); rec.Code/100 != 4 {
		t.Errorf("an unknown sink type: %d, want refused", rec.Code)
	}

	record := func(organizationID uuid.UUID, action string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, action, "user", uuid.New(), nil)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record(organization, "user.created")
	record(other, "user.deleted")
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatalf("forward: %v", err)
	}
	for path, credential := range map[string]string{"/http": "Bearer tok-http", "/splunk": "Splunk tok-splunk_hec", "/dd": "tok-datadog"} {
		got := sink.received(path)
		if len(got) != 1 || !strings.Contains(got[0], " "+credential+" ") || !strings.Contains(got[0], "user.created") || strings.Contains(got[0], "user.deleted") {
			t.Errorf("%s received %q; want the organisation's event once, with %q", path, got, credential)
		}
	}
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.received("/http"); len(got) != 1 {
		t.Errorf("forwarding again resent %d batches, want none new", len(got)-1)
	}

	sink.mu.Lock()
	sink.status = http.StatusInternalServerError
	sink.mu.Unlock()
	record(organization, "user.updated")
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []Sink `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 3 || list.Items[0].LastError == "" {
		t.Errorf("sinks after a failing endpoint %+v; want each to carry the error", list.Items)
	}

	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+ids["/http"], map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	sink.mu.Lock()
	sink.status = http.StatusOK
	sink.mu.Unlock()
	before := len(sink.received("/http"))
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.received("/http")) != before {
		t.Error("a disabled sink was forwarded to")
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+ids["/dd"], nil); rec.Code/100 != 2 {
		t.Errorf("delete: %d", rec.Code)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	if rec := dbtest.Do(t, asOther, http.MethodDelete, "/tenants/"+other.String()+"/log-sinks/"+ids["/splunk"], nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation deleting the sink: %d, want 404", rec.Code)
	}

	if _, err := NewService(pool).Create(ctx, organization, "http", "http://127.0.0.1:9/collect", "", audit.Actor{Type: "user"}); err == nil {
		t.Error("a sink to a private address was accepted")
	}
}

// TestForwardingKeepsUpOnceAndBacksOff checks that a sink receives a backlog
// larger than one batch in one round, with each event's metadata and user
// agent; that a sink another instance holds is left to it; and that a failing
// sink isn't tried again until its back-off passes.
func TestForwardingKeepsUpOnceAndBacksOff(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(pool, egress.DevelopmentPolicy())
	svc.SetCipher(box)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	sink := newCollector(t)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/log-sinks", map[string]string{"type": "http", "endpoint": sink.URL + "/http", "token": "tok"})
	var created Sink
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	record := func(n int) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for range n {
			e := audit.Actor{Type: "user", UserAgent: "Mozilla/5.0 test"}.Event(organization, "user.updated", "user", uuid.New(), map[string]any{"field": "name"})
			if err := audit.Record(ctx, tx, e); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	events := func() int {
		n := 0
		for _, r := range sink.received("/http") {
			n += strings.Count(r, `"action":"user.updated"`)
		}
		return n
	}

	record(2*forwardBatch + 7)
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatal(err)
	}
	if n := events(); n != 2*forwardBatch+7 {
		t.Errorf("one round forwarded %d of %d events", n, 2*forwardBatch+7)
	}
	if got := sink.received("/http"); len(got) == 0 || !strings.Contains(got[0], `"user_agent":"Mozilla/5.0 test"`) || !strings.Contains(got[0], `"metadata":{"field":"name"}`) {
		t.Errorf("forwarded %q; want each event's user agent and metadata", got)
	}

	record(1)
	if _, err := pool.Exec(ctx, `UPDATE organization.log_sinks SET leased_until = NOW() + INTERVAL '1 minute' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	before := events()
	if err := svc.forwardDue(ctx); err != nil || events() != before {
		t.Errorf("a sink another instance holds was forwarded to (%v)", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE organization.log_sinks SET leased_until = NULL WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}

	sink.mu.Lock()
	sink.status = http.StatusServiceUnavailable
	sink.mu.Unlock()
	if err := svc.forwardDue(ctx); err != nil {
		t.Fatal(err)
	}
	attempts := len(sink.received("/http"))
	sink.mu.Lock()
	sink.status = http.StatusOK
	sink.mu.Unlock()
	if err := svc.forwardDue(ctx); err != nil || len(sink.received("/http")) != attempts {
		t.Errorf("a failing sink was tried again before its back-off passed (%v)", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE organization.log_sinks SET next_attempt_at = NOW() - INTERVAL '1 second' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	// The collector keeps the refused request too: the held event, twice.
	if err := svc.forwardDue(ctx); err != nil || events() != before+2 {
		t.Errorf("after the back-off: %d events, want the held one delivered (%v)", events(), err)
	}
}

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
	base := "/tenants/" + organization.String() + "/log-sinks"
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
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/tenants/"+other.String()+"/log-sinks/"+saved.ID.String()+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation testing this destination: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'siem.sink_tested'`, organization); n != 3 {
		t.Errorf("%d tests audited, want 3", n)
	}
}
