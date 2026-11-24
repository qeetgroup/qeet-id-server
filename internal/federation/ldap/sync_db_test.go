//go:build integration

package ldap

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// directoryPerson is an Active Directory entry, enabled (512) or disabled (514).
func directoryPerson(dn, email string, enabled bool, usn int, groups ...string) dirEntry {
	control := "514"
	if enabled {
		control = "512"
	}
	return dirEntry{dn: dn, attrs: map[string]string{
		"mail": email, "cn": strings.TrimPrefix(strings.SplitN(dn, ",", 2)[0], "uid="),
		attrUserAccountControl: control, attrUSNChanged: strconv.Itoa(usn),
	}, multi: map[string][]string{groupsAttr: groups}}
}

type syncPeople struct {
	organization, connection uuid.UUID
	dir                      *directory
	svc                      *Service
	notices                  *notices
	ops                      *operations    // the directory activity the sync records
	manager                  dbtest.Account // may manage the organization's directory connections
}

const syncService = "cn=service,dc=example,dc=test"

// newSyncPeople stores an active connection to dir, with a member who manages connections.
func newSyncPeople(t *testing.T, dir *directory, with ...func(*Deps)) *syncPeople {
	t.Helper()
	organization := dbtest.Organization(t)
	if dir.binds == nil {
		dir.binds = map[string]string{}
	}
	dir.binds[syncService] = "service-secret"
	p := &syncPeople{organization: organization, dir: dir, notices: &notices{}, ops: &operations{}}
	p.connection = storedConnection(t, organization, dir.start(t), syncService)
	p.svc = directoryService(t, append([]func(*Deps){func(d *Deps) { d.Notifier, d.Observer = p.notices, p.ops }}, with...)...)
	p.manager = dbtest.User(t, organization, organization)
	dbtest.Assign(t, p.manager.ID, organization, dbtest.Role(t, organization, "connection.write"))
	return p
}

// signedIn links an account to dn, with two sessions and an application grant.
func (p *syncPeople) signedIn(t *testing.T, dn, email string) uuid.UUID {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	a := dbtest.UserAt(t, email, p.organization, p.organization)
	if _, err := pool.Exec(ctx, `
		INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email)
		VALUES ($1, $2, 'ldap', $3, $4, $5)`, a.ID, p.organization, p.connection, dn, email); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2), ($1, $2)`, a.ID, p.organization); err != nil {
		t.Fatalf("sessions: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')`, dbtest.Unique("grant"), a.ID, p.organization); err != nil {
		t.Fatalf("application grant: %v", err)
	}
	return a.ID
}

// sync runs the sync job with only this connection due.
func (p *syncPeople) sync(t *testing.T, full bool) SyncRun {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections
		SET sync_started_at = CASE WHEN id = $1 THEN NOW() - INTERVAL '1 hour' ELSE NOW() END,
		    full_sync_at = CASE WHEN id = $1 AND $2 THEN NULL ELSE full_sync_at END`, p.connection, full); err != nil {
		t.Fatal(err)
	}
	run, err := p.svc.SyncDue(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return run
}

// account is userID's status and suspension source.
func account(t *testing.T, userID uuid.UUID) string {
	t.Helper()
	var status, source string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT status, COALESCE(suspension_source, '') FROM account.users WHERE id = $1`, userID).Scan(&status, &source); err != nil {
		t.Fatal(err)
	}
	if source == "" {
		return status
	}
	return status + "/" + source
}

func liveSignIns(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT (SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL)
		+ (SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL)`, userID)
}

// syncEvents lists the sync's activity as "resource status reason", sorted.
func (p *syncPeople) syncEvents() []string {
	var out []string
	for _, op := range p.syncOps() {
		out = append(out, op.Resource+" "+strconv.Itoa(op.Status)+" "+op.Reason)
	}
	sort.Strings(out)
	return out
}

func (p *syncPeople) syncOps() []Operation {
	p.ops.mu.Lock()
	defer p.ops.mu.Unlock()
	var out []Operation
	for _, op := range p.ops.ops {
		if op.Operation == "sync" && op.ConnectionID == p.connection {
			out = append(out, op)
		}
	}
	return out
}

func (p *syncPeople) countOps(match func(Operation) bool) int {
	n := 0
	for _, op := range p.syncOps() {
		if match(op) {
			n++
		}
	}
	return n
}

// TestSyncSuspendsPeopleTheDirectoryDisables checks suspension, reactivation and
// full versus incremental runs.
func TestSyncSuspendsPeopleTheDirectoryDisables(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	dir := &directory{}
	p := newSyncPeople(t, dir)
	domain := dbtest.Domain(t, p.organization)
	const aliceDN, bobDN, carolDN, rootDN = "uid=alice,dc=example,dc=test", "uid=bob,dc=example,dc=test", "uid=carol,dc=example,dc=test", "uid=root,dc=example,dc=test"
	aliceMail, bobMail, carolMail, rootMail := dbtest.Unique("alice")+"@"+domain, dbtest.Unique("bob")+"@"+domain, dbtest.Unique("carol")+"@"+domain, dbtest.Unique("root")+"@"+domain
	alice, bob, carol, root := p.signedIn(t, aliceDN, aliceMail), p.signedIn(t, bobDN, bobMail), p.signedIn(t, carolDN, carolMail), p.signedIn(t, rootDN, rootMail)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, p.organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, root, p.organization, ownerRole)
	dir.set(map[string]dirEntry{
		"alice": directoryPerson(aliceDN, aliceMail, true, 100),
		"bob":   directoryPerson(bobDN, bobMail, false, 101),
		"carol": directoryPerson(carolDN, carolMail, true, 102),
		"root":  directoryPerson(rootDN, rootMail, false, 103),
	})

	if run := p.sync(t, false); run.Synced != 1 || run.Failed != 0 {
		t.Fatalf("first run: %+v, want one connection synced", run)
	}
	if got := account(t, bob); got != "suspended/ldap" {
		t.Errorf("bob, disabled in the directory: %s, want suspended by the LDAP sync", got)
	}
	if n := liveSignIns(t, bob); n != 0 {
		t.Errorf("bob keeps %d sessions and grants, want none", n)
	}
	for name, id := range map[string]uuid.UUID{"alice": alice, "carol": carol, "an owner the directory disabled": root} {
		if got, n := account(t, id), liveSignIns(t, id); got != "active" || n != 3 {
			t.Errorf("%s: %s with %d sessions and grants, want active with all 3", name, got, n)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'user.suspended'
		AND actor_type = 'ldap_sync' AND resource_id = $2 AND metadata->>'cause' = 'disabled_in_directory'`, p.organization, bob); n != 1 {
		t.Errorf("%d suspensions of bob recorded as the LDAP sync's, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'user.suspended'`, bob); n != 1 {
		t.Errorf("%d user.suspended events for bob, want 1", n)
	}
	if got := p.syncEvents(); got[0] != "connection 200 " || got[len(got)-1] != "user 409 " {
		t.Errorf("sync activity %q; want the run, and the owner kept (409, a warning)", got)
	}
	if n := p.countOps(func(op Operation) bool {
		return op.Resource == "user" && op.Status == 200 && op.UserID != nil && *op.UserID == bob && op.Subject == bobDN &&
			op.Params["change"] == "suspended" && op.Params["cause"] == causeDisabled
	}); n != 1 {
		t.Errorf("%d records of bob's suspension in the sync activity, want 1", n)
	}
	var cursor string
	var people int
	if err := pool.QueryRow(ctx, `SELECT sync_cursor, sync_people FROM organization.ldap_connections WHERE id = $1 AND full_sync_at IS NOT NULL`, p.connection).Scan(&cursor, &people); err != nil || cursor != "usn:103" || people != 4 {
		t.Errorf("after a full run: cursor %q, %d people, %v; want usn:103 and 4", cursor, people, err)
	}

	if run, err := p.svc.SyncDue(ctx); err != nil || run.Synced+run.Failed != 0 {
		t.Errorf("a run straight after: %+v, %v; want nothing due", run, err)
	}

	dir.set(map[string]dirEntry{
		"alice": directoryPerson(aliceDN, aliceMail, true, 100),
		"bob":   directoryPerson(bobDN, bobMail, true, 110),
		"root":  directoryPerson(rootDN, rootMail, false, 103),
	})
	p.sync(t, false)
	if last := dir.lastSearch(); !strings.Contains(last, "(uSNChanged>=104)") {
		t.Errorf("incremental run searched %q, want what changed after usn 103", last)
	}
	if got := account(t, bob); got != "active" {
		t.Errorf("bob, enabled again: %s, want active", got)
	}
	if got := account(t, carol); got != "active" {
		t.Errorf("carol after an incremental run: %s, want active until a full run", got)
	}
	p.sync(t, true)
	if got, n := account(t, carol), liveSignIns(t, carol); got != "suspended/ldap" || n != 0 {
		t.Errorf("carol, no longer listed, after a full run: %s with %d sign-ins, want suspended with none", got, n)
	}
	if got := account(t, alice); got != "active" {
		t.Errorf("alice: %s, want active", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'user.reactivated' AND actor_type = 'ldap_sync' AND resource_id = $2`, p.organization, bob); n != 1 {
		t.Errorf("%d reactivations of bob recorded, want 1", n)
	}
	if got := len(p.notices.of(p.manager.ID)); got != 0 {
		t.Errorf("%d notices to the manager of a connection that syncs, want none", got)
	}
}

// TestSyncChangesNothingWhenTheDirectoryFails checks that failed syncs suspend no
// one and alert the managers once, then on recovery.
func TestSyncChangesNothingWhenTheDirectoryFails(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	dir := &directory{}
	p := newSyncPeople(t, dir)
	domain := dbtest.Domain(t, p.organization)
	const aliceDN = "uid=alice,dc=example,dc=test"
	aliceMail := dbtest.Unique("alice") + "@" + domain
	alice := p.signedIn(t, aliceDN, aliceMail)
	dir.set(map[string]dirEntry{"alice": directoryPerson(aliceDN, aliceMail, false, 100)})

	down := &directory{}
	downURL := down.start(t)
	down.stop()
	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections SET server_url = $1 WHERE id = $2`, downURL, p.connection); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if run := p.sync(t, false); run.Failed != 1 {
			t.Fatalf("sync of an unreachable directory: %+v, want it failed", run)
		}
	}
	if got := account(t, alice); got != "active" {
		t.Errorf("alice after failed syncs: %s, want active", got)
	}
	unreachable := "connection 502 ldap.directory_unreachable"
	if got := strings.Join(p.syncEvents(), ","); got != unreachable+","+unreachable {
		t.Errorf("sync activity %q; want both runs failed, unreachable", got)
	}
	if sent := p.notices.of(p.manager.ID); len(sent) != 1 || sent[0].kind != "alert" || !strings.Contains(sent[0].about, "keep their access") {
		t.Errorf("manager told %+v; want one alert", sent)
	}

	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections SET server_url = $1 WHERE id = $2`, dir.url(), p.connection); err != nil {
		t.Fatal(err)
	}
	dir.mu.Lock()
	dir.failSearch = true
	dir.mu.Unlock()
	p.sync(t, false)
	if got := account(t, alice); got != "active" {
		t.Errorf("alice after a failed search: %s, want active", got)
	}
	if n := p.countOps(func(op Operation) bool { return op.Status == 502 && op.Reason == CodeSyncSearchFailed }); n != 1 {
		t.Errorf("%d failed searches recorded, want 1", n)
	}

	dir.mu.Lock()
	dir.failSearch = false
	dir.mu.Unlock()
	if run := p.sync(t, false); run.Synced != 1 {
		t.Fatalf("sync once the directory answers: %+v", run)
	}
	if got := account(t, alice); got != "suspended/ldap" {
		t.Errorf("alice once the directory answers: %s, want suspended", got)
	}
	sent := p.notices.of(p.manager.ID)
	if len(sent) != 2 || sent[1].kind != "info" {
		t.Errorf("manager told %+v; want the alert, then that it recovered", sent)
	}

	plain := &directory{}
	q := newSyncPeople(t, plain, production)
	q.signedIn(t, aliceDN, dbtest.Unique("alice")+"@"+dbtest.Domain(t, q.organization))
	if run := q.sync(t, false); run.Failed != 1 {
		t.Fatalf("sync without TLS: %+v, want it failed", run)
	}
	if got := q.syncEvents(); len(got) != 1 || got[0] != "connection 422 "+CodeTLSRequired || plain.bindsAs(syncService) != 0 {
		t.Errorf("sync without TLS: %v with %d binds; want refused with %s before any bind", got, plain.bindsAs(syncService), CodeTLSRequired)
	}
}

// TestSyncRefusesAnIncompleteAnswer checks the fail-safe, and that saving the
// connection accepts a directory that really shrank.
func TestSyncRefusesAnIncompleteAnswer(t *testing.T) {
	dir := &directory{}
	p := newSyncPeople(t, dir)
	domain := dbtest.Domain(t, p.organization)
	entries := map[string]dirEntry{}
	var people []uuid.UUID
	for i := range 5 {
		uid := "person" + strconv.Itoa(i)
		dn, mail := "uid="+uid+",dc=example,dc=test", dbtest.Unique(uid)+"@"+domain
		people = append(people, p.signedIn(t, dn, mail))
		entries[uid] = directoryPerson(dn, mail, true, 100+i)
	}
	activeCount := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = ANY($1) AND status = 'active'`, people)
	}

	p.sync(t, true)
	if got := strings.Join(p.syncEvents(), ","); got != "connection 412 "+CodeSyncEmptyResult || activeCount() != 5 {
		t.Errorf("a directory listing no one: %q with %d of 5 active; want refused, everyone active", got, activeCount())
	}
	if sent := p.notices.of(p.manager.ID); len(sent) != 1 || sent[0].kind != "alert" {
		t.Errorf("manager told %+v; want one alert", sent)
	}

	dropped := func() int {
		return p.countOps(func(op Operation) bool { return op.Status == 412 && op.Reason == CodeSyncPeopleDropped })
	}
	dir.set(map[string]dirEntry{"person0": entries["person0"]})
	p.sync(t, true)
	if dropped() != 1 || activeCount() != 5 {
		t.Errorf("a directory listing one of five: %d refusals, %d active; want refused, everyone active", dropped(), activeCount())
	}

	ctx := dbtest.Context(t)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.ldap_connections SET sync_people = 20, sync_cursor = 'usn:100' WHERE id = $1`, p.connection); err != nil {
		t.Fatal(err)
	}
	dir.set(map[string]dirEntry{"person0": entries["person0"], "person1": entries["person1"], "person2": entries["person2"]})
	p.sync(t, true)
	if dropped() != 2 || activeCount() != 5 {
		t.Errorf("a directory listing 3 of the 20 people before: %d refusals, %d active; want refused, everyone active", dropped(), activeCount())
	}

	if _, err := p.svc.Update(ctx, p.connection, p.organization, UpdateInput{}, audit.Actor{Type: "system"}); err != nil {
		t.Fatal(err)
	}
	p.sync(t, false)
	if activeCount() != 3 {
		t.Errorf("after the connection was saved, %d of 5 active; want the 3 the directory lists", activeCount())
	}
}

// TestSyncUpdatesGroups checks that a sync follows the connection's group mappings.
func TestSyncUpdatesGroups(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	dir := &directory{}
	p := newSyncPeople(t, dir)
	domain := dbtest.Domain(t, p.organization)
	const aliceDN, engineering = "uid=alice,dc=example,dc=test", "cn=engineering,ou=groups,dc=example,dc=test"
	aliceMail := dbtest.Unique("alice") + "@" + domain
	alice := p.signedIn(t, aliceDN, aliceMail)
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, p.organization, dbtest.Unique("Engineering")).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id) VALUES ($1, $2, $3, $4)`,
		p.organization, p.connection, engineering, group); err != nil {
		t.Fatal(err)
	}
	member := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1 AND user_id = $2 AND source_connection_id = $3`, group, alice, p.connection)
	}

	dir.set(map[string]dirEntry{"alice": directoryPerson(aliceDN, aliceMail, true, 100, engineering)})
	p.sync(t, false)
	if member() != 1 {
		t.Fatal("alice, in the mapped directory group, wasn't put in the group")
	}
	dir.set(map[string]dirEntry{"alice": directoryPerson(aliceDN, aliceMail, true, 101)})
	p.sync(t, false)
	if member() != 0 {
		t.Error("alice, taken out of the directory group, is still in the group")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND actor_type = 'ldap_sync'
		AND action IN ('group.member_added', 'group.member_removed') AND resource_id = $2`, p.organization, group); n != 2 {
		t.Errorf("%d group changes recorded as the LDAP sync's, want 2", n)
	}
	if got := account(t, alice); got != "active" {
		t.Errorf("alice: %s, want active", got)
	}
	if got := strings.Join(p.syncEvents(), ","); got != "connection 200 ,connection 200 ,user 200 ,user 200 " {
		t.Errorf("sync activity %q; want alice's change and the run, twice", got)
	}
}
