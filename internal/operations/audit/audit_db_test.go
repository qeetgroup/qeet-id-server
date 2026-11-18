//go:build integration

package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// record writes one audit event for organization and returns its id.
func record(t *testing.T, organization uuid.UUID, action string) uuid.UUID {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := Record(ctx, tx, Actor{Type: "system"}.Event(organization, action, "user", uuid.New(), nil)); err != nil {
		t.Fatalf("record %s: %v", action, err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit.events WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1`, organization).Scan(&id); err != nil {
		t.Fatalf("read back %s: %v", action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id
}

// TestAuditEventsStayInTheirOrganization checks that one organization can neither read nor
// verify another organization's audit trail, even when it pages from one of its
// event ids.
func TestAuditEventsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminB := dbtest.User(t, organizationB, organizationB)
	eventA := record(t, organizationA, "user.created")
	record(t, organizationA, "user.updated")
	eventB := record(t, organizationB, "user.created")

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Reader: NewReader(pool), Verifier: NewVerifier(pool, nil)}).Mount)
	for _, path := range []string{"/organizations/" + organizationA.String() + "/audit", "/organizations/" + organizationA.String() + "/audit/verify"} {
		if rec := dbtest.Do(t, asB, http.MethodGet, path, nil); rec.Code != http.StatusForbidden {
			t.Errorf("organization B GET %s: status %d, want 403", path, rec.Code)
		}
	}
	own := "/organizations/" + organizationB.String() + "/audit"
	for _, path := range []string{own, own + "?q=user", own + "?cursor=" + eventA.String()} {
		ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path, nil))
		if slices.Contains(ids, eventA) {
			t.Errorf("organization B GET %s returned organization A's event", path)
		}
		if path == own && !slices.Equal(ids, []uuid.UUID{eventB}) {
			t.Errorf("organization B's trail = %v, want only %s", ids, eventB)
		}
	}

	res, err := NewVerifier(pool, nil).Verify(ctx, &organizationB)
	if err != nil || !res.OK || res.RowsChecked != 1 {
		t.Errorf("verify organization B's chain: %+v, %v; want 1 valid row", res, err)
	}
}

// TestAuditListPagesThroughEveryRow checks that following next_cursor returns
// each of the organization's events exactly once, newest first, including events
// that share a time.
func TestAuditListPagesThroughEveryRow(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	at := time.Now().UTC().Truncate(time.Microsecond)
	for range 4 {
		record(t, organization, "user.updated")
	}
	// A run of events at one time, which the id breaks ties between.
	for range 4 {
		if _, err := dbtest.Pool(t).Exec(ctx, `
			INSERT INTO audit.events (organization_id, actor_type, action, resource_type, created_at)
			VALUES ($1, 'system', 'user.updated', 'user', $2)
		`, organization, at.Add(-time.Hour)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	var want []uuid.UUID
	rows, err := dbtest.Pool(t).Query(ctx, `SELECT id FROM audit.events WHERE organization_id = $1 ORDER BY created_at DESC, id DESC`, organization)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		want = append(want, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Reader: NewReader(dbtest.Pool(t))}).Mount)
	var got []uuid.UUID
	path := "/organizations/" + organization.String() + "/audit?limit=3"
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("the audit list did not reach its last page")
		}
		rec := dbtest.Do(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body)
		}
		var page struct {
			Items []struct {
				ID uuid.UUID `json:"id"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		dbtest.Decode(t, rec, &page)
		for _, item := range page.Items {
			got = append(got, item.ID)
		}
		if page.NextCursor == "" {
			break
		}
		path = "/organizations/" + organization.String() + "/audit?limit=3&cursor=" + page.NextCursor
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged audit list = %v\nwant %v", got, want)
	}
}

// TestVerifyReadsTheChainInPages checks that verification walks a chain longer
// than one page to its end, and still finds a row altered on a later page.
func TestVerifyReadsTheChainInPages(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	var ids []uuid.UUID
	for range 7 {
		ids = append(ids, record(t, organization, "user.updated"))
	}
	verifyPageSize = 2
	t.Cleanup(func() { verifyPageSize = 5000 })

	res, err := NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &organization)
	if err != nil || !res.OK || res.RowsChecked != 7 {
		t.Fatalf("verify: %+v, %v; want 7 valid rows", res, err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.deleted' WHERE id = $1 AND organization_id = $2`, ids[5], organization); err != nil {
		t.Fatal(err)
	}
	res, err = NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &organization)
	if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != ids[5] || res.RowsChecked != 5 || res.ReasonCode != ChainRowHashMismatch {
		t.Errorf("verify an altered chain: %+v, %v; want broken at %s after 5 rows, its row hash wrong", res, err, ids[5])
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET prev_hash = 'x' WHERE id = $1 AND organization_id = $2`, ids[2], organization); err != nil {
		t.Fatal(err)
	}
	res, err = NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &organization)
	if err != nil || res.BrokenAtID == nil || *res.BrokenAtID != ids[2] || res.ReasonCode != ChainPrevHashMismatch {
		t.Errorf("verify a relinked chain: %+v, %v; want broken at %s, its link wrong", res, err, ids[2])
	}
}

// TestChainSurvivesAnInstanceWhoseClockIsAhead checks that a row written by
// an instance whose clock is behind the chain's tip still goes after it, so
// the chain stays whole when two instances disagree about the time.
func TestChainSurvivesAnInstanceWhoseClockIsAhead(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	clock = func() time.Time { return time.Now().Add(time.Minute) }
	ahead := record(t, organization, "user.updated")
	clock = time.Now
	t.Cleanup(func() { clock = time.Now })
	behind := record(t, organization, "user.deleted")

	var first uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM audit.events WHERE organization_id = $1 ORDER BY created_at, id LIMIT 1`, organization).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first != ahead {
		t.Errorf("the chain starts at %s, want the earlier write %s before %s", first, ahead, behind)
	}
	if res, err := NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &organization); err != nil || !res.OK || res.RowsChecked != 2 {
		t.Errorf("verify: %+v, %v; want both rows valid", res, err)
	}
}

// TestEventsNameWhatTheyAreAbout checks that an audit row names its resource
// and the role or group its metadata gives an id for, as they are when it is
// written, but never a person, whose name would outlive their erasure; that a
// target already gone keeps the name the caller gave; that another
// organization's role is not named; that a name the caller gave is kept; and
// that the chain still verifies.
func TestEventsNameWhatTheyAreAbout(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	unnamed := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET display_name = 'Asha Rao' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	var role, otherRole, group, policy uuid.UUID
	for _, q := range []struct {
		dst  *uuid.UUID
		sql  string
		args []any
	}{
		{&role, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, 'auditor') RETURNING id`, []any{organization}},
		{&otherRole, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, 'theirs') RETURNING id`, []any{other}},
		{&group, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Finance') RETURNING id`, []any{organization}},
		{&policy, `INSERT INTO auth.abac_policies (organization_id, name, effect, resource_type, action) VALUES ($1, 'office_hours', 'deny', '*', '*') RETURNING id`, []any{organization}},
	} {
		if err := pool.QueryRow(ctx, q.sql, q.args...).Scan(q.dst); err != nil {
			t.Fatal(err)
		}
	}

	actor := Actor{Type: "system"}
	gone := uuid.New()
	events := []struct {
		event Event
		want  map[string]any
	}{
		{actor.Event(organization, "role.assigned", "user", person.ID, map[string]any{"role_id": role}),
			map[string]any{"target_name": nil, "role_name": "auditor"}},
		{actor.Event(organization, "group.member_added", "group", group, map[string]any{"user_id": unnamed.ID.String()}),
			map[string]any{"target_name": "Finance", "user_name": nil}},
		{actor.Event(organization, "abac_policy.updated", "abac_policy", policy, nil),
			map[string]any{"target_name": "office_hours"}},
		{actor.Event(organization, "group.deleted", "group", gone, map[string]any{"name": "Old team"}),
			map[string]any{"target_name": "Old team"}},
		{actor.Event(organization, "role.group_assigned", "group", group, map[string]any{"role_id": otherRole}),
			map[string]any{"target_name": "Finance", "role_name": nil}},
		{actor.Event(organization, "group.updated", "group", group, map[string]any{"target_name": "as given"}),
			map[string]any{"target_name": "as given"}},
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, e := range events {
		if err := Record(ctx, tx, e.event); err != nil {
			t.Fatalf("record %s: %v", e.event.Action, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT metadata FROM audit.events WHERE organization_id = $1 ORDER BY created_at`, organization)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	for rows.Next() {
		var m map[string]any
		if err := rows.Scan(&m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	if rows.Close(); len(got) != len(events) {
		t.Fatalf("%d rows, want %d", len(got), len(events))
	}
	for i, e := range events {
		for k, want := range e.want {
			if v, ok := got[i][k]; (want == nil && ok) || (want != nil && v != want) {
				t.Errorf("%s: metadata %s = %v, want %v (%v)", e.event.Action, k, v, want, got[i])
			}
		}
	}
	if res, err := NewVerifier(pool, nil).Verify(ctx, &organization); err != nil || !res.OK {
		t.Errorf("verify the labelled chain: %+v, %v", res, err)
	}
}

// onShard makes Record put platform events on shard until t ends.
func onShard(t *testing.T, shard int16) {
	t.Helper()
	orig := platformShard
	platformShard = func(pgx.Tx) int16 { return shard }
	t.Cleanup(func() { platformShard = orig })
}

// recordPlatform writes one platform event on shard, committed, and returns
// its id.
func recordPlatform(t *testing.T, shard int16, action string) uuid.UUID {
	t.Helper()
	onShard(t, shard)
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := Record(ctx, tx, Actor{Type: "system"}.PlatformEvent(action, "user", uuid.New(), nil)); err != nil {
		t.Fatalf("record %s on chain %d: %v", action, shard, err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit.events WHERE organization_id IS NULL AND chain_shard = $1
		ORDER BY created_at DESC, id DESC LIMIT 1`, shard).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// inTx runs fn in a transaction that is rolled back after, with a Verifier
// that reads through it, so a test can tamper with the platform chains, which
// every test shares, without leaving them broken.
func inTx(t *testing.T, fn func(tx pgx.Tx, v *Verifier)) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	fn(tx, &Verifier{q: dbgen.New(tx)})
}

// TestPlatformShardFollowsTheConnection checks that a transaction's platform
// events all go on its connection's chain.
func TestPlatformShardFollowsTheConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var pid int64
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if got, want := platformShard(tx), int16(pid%PlatformChainShards); got != want {
		t.Errorf("platform chain %d for backend %d, want %d", got, pid, want)
	}
}

// TestPlatformChainsDontWaitForEachOther checks that a transaction writing to
// one platform chain doesn't hold up a writer on another, while a second
// writer on the same chain waits for the first.
func TestPlatformChainsDontWaitForEachOther(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		// A writer that would wait gives up quickly instead.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	write := func(tx pgx.Tx, shard int16) error {
		onShard(t, shard)
		return Record(ctx, tx, Actor{Type: "system"}.PlatformEvent("auth.signed_up", "user", uuid.New(), nil))
	}

	first := begin()
	if err := write(first, 1); err != nil {
		t.Fatalf("first writer on chain 1: %v", err)
	}
	other := begin()
	if err := write(other, 2); err != nil {
		t.Errorf("a writer on chain 2 while chain 1 is held: %v, want no wait", err)
	}
	same := begin()
	var pgErr *pgconn.PgError
	if err := write(same, 1); !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("a second writer on chain 1 while it is held: %v, want it to wait (lock_not_available)", err)
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// writeAsTheSinglePlatformChain writes a platform row as the release before
// the platform chains wrote one: chained to chain 0's tip and hashed without a
// shard, the insert naming no chain_shard. It returns its id.
func writeAsTheSinglePlatformChain(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := lockChain(ctx, tx, nil, 0); err != nil {
		t.Fatal(err)
	}
	var prev string
	var tipAt time.Time
	if err := tx.QueryRow(ctx, `SELECT row_hash, created_at FROM audit.events WHERE organization_id IS NULL AND chain_shard = 0
		AND row_hash IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&prev, &tipAt); err != nil {
		t.Fatal(err)
	}
	e := Event{ActorType: "system", Action: "auth.signed_up", ResourceType: "user"}
	id, at, meta := uuid.New(), tipAt.Add(time.Millisecond), []byte("{}")
	raw, err := canonicalize(e, 0, id, at, meta, strings.TrimSpace(prev))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "chain_shard") {
		t.Fatalf("a chain 0 row's hashed form names its chain: %s", raw)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit.events (id, actor_type, action, resource_type, metadata, created_at, prev_hash, row_hash, user_agent, request_id)
		VALUES ($1, 'system', 'auth.signed_up', 'user', '{}', $2, $3, $4, '', '')`,
		id, at, strings.TrimSpace(prev), hashHex(raw)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRecordAloneCommitsTheEvent checks that RecordAlone's event is committed
// on its organization's chain, and a platform event on a platform chain, both
// left verifiable.
func TestRecordAloneCommitsTheEvent(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	actor := Actor{Type: "system"}
	if err := RecordAlone(ctx, pool, actor.EventIn(&organization, "thing.refused", "thing", uuid.New(), nil)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'thing.refused'`, organization); n != 1 {
		t.Errorf("organization events: %d, want 1", n)
	}
	// The platform chains are shared by every test: use one no other test
	// reads, and take the row off again so no later run checkpoints it.
	resource := uuid.New()
	onShard(t, 15)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM audit.events WHERE organization_id IS NULL AND resource_id = $1`, resource); err != nil {
			t.Error(err)
		}
	})
	if err := RecordAlone(ctx, pool, actor.EventIn(nil, "thing.platform", "thing", resource, nil)); err != nil {
		t.Fatalf("record platform event: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id IS NULL AND resource_id = $1`, resource); n != 1 {
		t.Errorf("platform events: %d, want 1", n)
	}
	if res, err := NewVerifier(pool, nil).Verify(ctx, &organization); err != nil || !res.OK || res.RowsChecked != 1 {
		t.Errorf("verify the organization's chain: %+v, %v; want 1 valid row", res, err)
	}
}

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

	organization := dbtest.Organization(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, meta := range []map[string]any{nil, {"geo": "given"}} {
		if err := Record(ctx, tx, Actor{Type: "system"}.Event(organization, "test.placed", "user", uuid.New(), meta)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1
		AND metadata->'geo'->>'country' = 'IN' AND metadata->'geo'->>'city' = 'Pune'`, organization); n != 1 {
		t.Errorf("%d events placed in Pune, IN, want the one that didn't say", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND metadata->>'geo' = 'given'`, organization); n != 1 {
		t.Errorf("an event's own geo was replaced")
	}
	res, err := NewVerifier(dbtest.Pool(t), nil).Verify(dbtest.Context(t), &organization)
	if err != nil || !res.OK {
		t.Errorf("the chain after placed events: %+v, %v", res, err)
	}
}

// TestEventsNameTheKeyOrAgentThatActed checks that an event an API key, agent
// or service principal caused records its id as actor_id, and a person's
// event doesn't.
func TestEventsNameTheKeyOrAgentThatActed(t *testing.T) {
	organization := dbtest.Organization(t)
	key := uuid.NewString()
	for _, c := range []struct {
		actorType, subject string
	}{{"api_key", key}, {"user", uuid.NewString()}} {
		ctx := httpx.WithPrincipal(dbtest.Context(t), &httpx.Principal{ActorType: c.actorType, Subject: c.subject})
		tx, err := dbtest.Pool(t).Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := Record(ctx, tx, Actor{Type: c.actorType}.Event(organization, "test.acted", "user", uuid.New(), nil)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND metadata->>'actor_id' = $2 AND actor_type = 'api_key'`, organization, key); n != 1 {
		t.Errorf("%d events name the key, want its one", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND actor_type = 'user' AND metadata ? 'actor_id'`, organization); n != 0 {
		t.Errorf("a person's event names an actor_id")
	}
}
