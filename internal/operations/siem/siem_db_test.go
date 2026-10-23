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

// TestSinksForwardTheOrganisationsEvents checks that each kind of log sink
// receives its organisation's new audit events, with its credential, once,
// and no other organisation's; that a failing endpoint is recorded; that a
// disabled sink receives nothing; and that sinks are managed per organisation.
func TestSinksForwardTheOrganisationsEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(pool, egress.DevelopmentPolicy())
	svc.SetCipher(box)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	sink := newCollector(t)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + tenant.String() + "/log-sinks"

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

	record := func(tenantID uuid.UUID, action string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(tenantID, action, "user", uuid.New(), nil)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record(tenant, "user.created")
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
	record(tenant, "user.updated")
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

	if _, err := NewService(pool).Create(ctx, tenant, "http", "http://127.0.0.1:9/collect", "", audit.Actor{Type: "user"}); err == nil {
		t.Error("a sink to a private address was accepted")
	}
}
