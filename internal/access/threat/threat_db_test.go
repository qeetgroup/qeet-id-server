//go:build integration

package threat

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestLockoutsCountAsOpenIncidents checks that the anomaly summary counts what
// the sign-in lockouts record (status rate-limited) as open until resolved,
// each affected account once, and critical events as high severity.
func TestLockoutsCountAsOpenIncidents(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	victim := dbtest.User(t, organization, organization)
	dbtest.User(t, other, other)

	lock := auth.AccountLock{Email: victim.Email, Network: "203.0.113.0/24", Counter: auth.CounterAccount,
		Reason: "10 failed sign-ins", Failures: 10, Threshold: 10, Window: 15 * time.Minute, LockedUntil: time.Now().Add(15 * time.Minute)}
	svc.OnAccountLocked(ctx, lock)
	svc.OnAccountLocked(ctx, lock)
	if err := svc.Record(ctx, Event{OrganizationID: organization, Type: "credential_stuffing", Severity: "critical", Detail: "burst"}); err != nil {
		t.Fatal(err)
	}

	sum, err := svc.Summary(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Open != 3 || sum.AffectedAccounts != 1 || sum.HighSeverity24h != 3 || sum.Resolved24h != 0 {
		t.Errorf("summary %+v, want 3 open (2 rate-limited, 1 open), 1 affected account, 3 high or critical", *sum)
	}
	page, err := svc.List(ctx, organization, 10, paging.Cursor{}, "")
	if err != nil {
		t.Fatal(err)
	}
	events := page.Items
	if len(events) != 3 {
		t.Fatalf("list: %d events, %v", len(events), err)
	}
	for _, e := range events {
		if e.UserID != nil {
			if err := svc.Resolve(ctx, e.ID, organization, audit.Actor{Type: "user"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if sum, _ = svc.Summary(ctx, organization); sum.Open != 1 || sum.AffectedAccounts != 0 || sum.Resolved24h != 2 {
		t.Errorf("after resolving the lockouts: %+v, want 1 open, 0 affected, 2 resolved", *sum)
	}
	if sum, _ = svc.Summary(ctx, other); sum.Open != 0 {
		t.Errorf("another organization's summary: %+v, want nothing", *sum)
	}
}

// TestSprayCountsTheAccountsItTargeted checks that a password spray adds the
// accounts it targeted in each organization to that organization's affected
// accounts, once each, and names none of another organization's accounts.
func TestSprayCountsTheAccountsItTargeted(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	a, b, c := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	elsewhere := dbtest.User(t, other, other)
	svc.OnAccountLocked(ctx, auth.AccountLock{Email: a.Email, Network: "203.0.113.0/24", Counter: auth.CounterAccount,
		Reason: "10 failed sign-ins", Failures: 10, Threshold: 10, Window: 15 * time.Minute, LockedUntil: time.Now().Add(15 * time.Minute)})
	accounts := []string{a.Email, b.Email, c.Email, elsewhere.Email, "nobody@example.test"}
	for i := range accounts {
		accounts[i] = strings.ToLower(accounts[i])
	}
	svc.OnSourceThrottled(ctx, auth.SourceThrottle{Network: "198.51.100.0/24", Reason: "spray", Accounts: accounts,
		Window: 15 * time.Minute, ThrottledUntil: time.Now().Add(15 * time.Minute)})

	if sum, err := svc.Summary(ctx, organization); err != nil || sum.AffectedAccounts != 3 {
		t.Errorf("summary %+v (%v), want the three targeted accounts, the locked one counted once", sum, err)
	}
	if sum, err := svc.Summary(ctx, other); err != nil || sum.AffectedAccounts != 1 {
		t.Errorf("the other organization's summary %+v (%v), want its one targeted account", sum, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.security_events WHERE organization_id = $1 AND type = 'password_spraying'
		AND metadata->'targeted_user_ids' @> to_jsonb($2::text)`, organization, elsewhere.ID.String()); n != 0 {
		t.Error("an organization's spray event names another organization's account")
	}
}

// TestResolvingAnAnomalyIsAudited checks that an administrator resolving an
// anomaly is recorded in their organization with what the anomaly was, and
// that another organization can neither resolve it nor leave a record of it.
func TestResolvingAnAnomalyIsAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	h := &Handler{Service: svc}
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin, victim := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	otherAdmin := dbtest.User(t, other, other)
	if err := svc.Record(ctx, Event{OrganizationID: organization, UserID: &victim.ID, Type: "credential_stuffing", Severity: "high", Detail: "burst"}); err != nil {
		t.Fatal(err)
	}
	page, err := svc.List(ctx, organization, 10, paging.Cursor{}, "")
	if err != nil {
		t.Fatal(err)
	}
	events := page.Items
	if len(events) != 1 {
		t.Fatalf("list: %d events, %v", len(events), err)
	}
	id := events[0].ID
	resolve := func(by uuid.UUID, in uuid.UUID) int {
		path := "/organizations/" + in.String() + "/security/anomalies/" + id.String() + "/resolve"
		return dbtest.Do(t, dbtest.Serve(dbtest.Principal(by, in), h.Mount), http.MethodPost, path, nil).Code
	}

	if code := resolve(otherAdmin.ID, other); code != http.StatusNotFound {
		t.Errorf("another organization resolves the anomaly: %d, want 404", code)
	}
	if code := resolve(admin.ID, organization); code != http.StatusOK {
		t.Fatalf("resolve: %d", code)
	}
	var raw []byte
	if err := dbtest.Pool(t).QueryRow(ctx, `
		SELECT metadata FROM audit.events
		WHERE organization_id = $1 AND action = 'anomaly.resolved' AND resource_type = 'security_event' AND resource_id = $2 AND actor_user_id = $3`,
		organization, id, admin.ID).Scan(&raw); err != nil {
		t.Fatalf("the resolution's audit record: %v", err)
	}
	var got struct {
		Type, Severity string
		UserID         uuid.UUID `json:"user_id"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.Type != "credential_stuffing" || got.Severity != "high" || got.UserID != victim.ID {
		t.Errorf("recorded %s, want the anomaly's type, severity and account", raw)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'anomaly.resolved' AND resource_id = $1`, id); n != 1 {
		t.Errorf("%d resolutions recorded, want 1", n)
	}
	if code := resolve(admin.ID, organization); code != http.StatusNotFound {
		t.Errorf("resolve again: %d, want 404", code)
	}
}

// TestAnomaliesArePagedAndSayWhoResolvedThem checks that anomalies page by
// cursor with a total, filter by status, and name who resolved one.
func TestAnomaliesArePagedAndSayWhoResolvedThem(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	for range 3 {
		if err := svc.Record(ctx, Event{OrganizationID: organization, Type: "credential_stuffing", Severity: "high", Detail: "burst"}); err != nil {
			t.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/security/anomalies"
	var page Page
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"?limit=2", nil), &page)
	if page.Total != 3 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %d of %d, cursor %q", len(page.Items), page.Total, page.NextCursor)
	}
	id := page.Items[0].ID
	if rec := dbtest.Do(t, h, http.MethodPost, base+"/"+id.String()+"/resolve", nil); rec.Code/100 != 2 {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"?status=resolved", nil), &page)
	if page.Total != 1 || page.Items[0].ID != id || page.Items[0].ResolvedBy == nil || *page.Items[0].ResolvedBy != admin.ID ||
		page.Items[0].ResolvedByEmail == nil || *page.Items[0].ResolvedByEmail != admin.Email {
		t.Errorf("resolved anomalies: %+v, want the one, resolved by the admin", page)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"?status=open", nil), &page)
	if page.Total != 2 {
		t.Errorf("open anomalies: %d, want 2", page.Total)
	}
}
