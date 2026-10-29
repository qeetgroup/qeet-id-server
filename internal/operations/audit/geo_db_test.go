//go:build integration

package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestEventsSayWhereTheyCameFrom checks that an event recorded for a request
// the trusted proxy placed keeps its country and city in its metadata, under
// the chain's hash, and that an event saying so itself keeps its own.
func TestEventsSayWhereTheyCameFrom(t *testing.T) {
	httpx.SetGeoCountryHeader("CloudFront-Viewer-Country")
	httpx.SetGeoCityHeader("CloudFront-Viewer-City")
	t.Cleanup(func() { httpx.SetGeoCountryHeader(""); httpx.SetGeoCityHeader("") })
	var ctx context.Context
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("CloudFront-Viewer-Country", "IN")
	req.Header.Set("CloudFront-Viewer-City", "Pune")
	httpx.GeoCountryContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).
		ServeHTTP(httptest.NewRecorder(), req)

	tenant := dbtest.Tenant(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, meta := range []map[string]any{nil, {"geo": "given"}} {
		if err := Record(ctx, tx, Actor{Type: "system"}.Event(tenant, "test.placed", "user", uuid.New(), meta)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1
		AND metadata->'geo'->>'country' = 'IN' AND metadata->'geo'->>'city' = 'Pune'`, tenant); n != 1 {
		t.Errorf("%d events placed in Pune, IN, want the one that didn't say", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND metadata->>'geo' = 'given'`, tenant); n != 1 {
		t.Errorf("an event's own geo was replaced")
	}
	res, err := NewVerifier(dbtest.Pool(t)).Verify(dbtest.Context(t), &tenant)
	if err != nil || !res.OK {
		t.Errorf("the chain after placed events: %+v, %v", res, err)
	}
}

// TestEventsNameTheKeyOrAgentThatActed checks that an event an API key, agent
// or service principal caused records its id as actor_id, and a person's
// event doesn't.
func TestEventsNameTheKeyOrAgentThatActed(t *testing.T) {
	tenant := dbtest.Tenant(t)
	key := uuid.NewString()
	for _, c := range []struct {
		actorType, subject string
	}{{"api_key", key}, {"user", uuid.NewString()}} {
		ctx := httpx.WithPrincipal(dbtest.Context(t), &httpx.Principal{ActorType: c.actorType, Subject: c.subject})
		tx, err := dbtest.Pool(t).Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := Record(ctx, tx, Actor{Type: c.actorType}.Event(tenant, "test.acted", "user", uuid.New(), nil)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND metadata->>'actor_id' = $2 AND actor_type = 'api_key'`, tenant, key); n != 1 {
		t.Errorf("%d events name the key, want its one", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND actor_type = 'user' AND metadata ? 'actor_id'`, tenant); n != 0 {
		t.Errorf("a person's event names an actor_id")
	}
}
