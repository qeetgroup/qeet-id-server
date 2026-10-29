//go:build integration

package decisionlog

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestDecisionsAreKeptAndListed checks that recorded decisions are written in
// the background with who asked, are written before Run returns, and list
// newest first, a page at a time, by subject, source and answer, in their
// tenant only.
func TestDecisionsAreKeptAndListed(t *testing.T) {
	ctx := dbtest.Context(t)
	log := New(dbtest.Pool(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asked := httpx.WithPrincipal(ctx, &httpx.Principal{UserID: &admin.ID, TenantID: &tenant, ActorType: "user"})

	running, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); log.Run(running) }()
	subject := uuid.NewString()
	log.Record(asked, Entry{TenantID: tenant, Source: SourceCheck, Subject: subject, Resource: "permission", Action: "user.read",
		Allowed: true, Model: "rbac", Rule: "admin", ReasonCode: "authz.role_grant"})
	log.Record(asked, Entry{TenantID: tenant, Source: SourceAuthZEN, Subject: subject, Resource: "document:plan", Action: "edit",
		Allowed: false, Model: "none", ReasonCode: "authz.nothing_allows"})
	log.Record(asked, Entry{TenantID: tenant, Source: SourceRelationCheck, Subject: uuid.NewString(), Resource: "document:plan", Action: "view", Allowed: true})
	log.Record(ctx, Entry{TenantID: other, Source: SourceCheck, Subject: subject, Action: "user.read", Allowed: true})
	stop()
	wg.Wait()

	page, err := log.List(ctx, tenant, Filter{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %+v, %v; want 2 with a cursor", page, err)
	}
	rest, err := log.List(ctx, tenant, Filter{Limit: 2, Cursor: page.NextCursor})
	if err != nil || len(rest.Items) != 1 || rest.NextCursor != "" {
		t.Fatalf("second page: %+v, %v; want the last one", rest, err)
	}
	if c := rest.Items[0]; c.Source != SourceCheck || c.CallerType != "user" || c.CallerID == nil || *c.CallerID != admin.ID || c.Rule != "admin" {
		t.Errorf("the oldest decision %+v; want the check, asked by the admin, decided by admin", c)
	}
	refused := false
	theirs, err := log.List(ctx, tenant, Filter{Subject: subject, Allowed: &refused})
	if err != nil || len(theirs.Items) != 1 || theirs.Items[0].Source != SourceAuthZEN {
		t.Errorf("the subject's refusals: %+v, %v; want the AuthZEN one", theirs, err)
	}
	if bySource, err := log.List(ctx, tenant, Filter{Source: SourceRelationCheck}); err != nil || len(bySource.Items) != 1 {
		t.Errorf("relationship checks: %+v, %v; want one", bySource, err)
	}
	if others, err := log.List(ctx, other, Filter{}); err != nil || len(others.Items) != 1 {
		t.Errorf("the other tenant's decisions: %+v, %v; want its one", others, err)
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Log: log}).Mount)
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+other.String()+"/authorization/decisions", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another tenant's decisions over HTTP: %d, want 403", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/authorization/decisions?allowed=maybe", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("allowed=maybe: %d, want 400", rec.Code)
	}

	var nilLog *Log
	nilLog.Record(ctx, Entry{TenantID: tenant}) // a nil log keeps nothing, and doesn't panic
}
