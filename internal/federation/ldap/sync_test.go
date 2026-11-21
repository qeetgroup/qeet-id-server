package ldap

import (
	"errors"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestListFilter checks that a sync lists everyone the user filter can find.
func TestListFilter(t *testing.T) {
	for in, want := range map[string]string{
		"(uid=%s)": "(uid=*)",
		"(&(objectClass=user)(sAMAccountName=%s))":    "(&(objectClass=user)(sAMAccountName=*))",
		"(&(objectClass=person)(|(uid=%s)(mail=%s)))": "(&(objectClass=person)(|(uid=*)(mail=*)))",
	} {
		if got, err := listFilter(in); err != nil || got != want {
			t.Errorf("listFilter(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"(objectClass=user)", "(uid=%s", ""} {
		if _, err := listFilter(in); !errors.Is(err, ErrSyncFilterInvalid) {
			t.Errorf("listFilter(%q): %v, want %v", in, err, ErrSyncFilterInvalid)
		}
	}
}

// TestSyncCursor checks incremental runs read from, and move, their change mark.
func TestSyncCursor(t *testing.T) {
	for cursor, want := range map[string]string{
		"usn:41":                 "(uSNChanged>=42)",
		"ts:20261121093000Z":     "(modifyTimestamp>=20261121093000Z)",
		"ts:20261121093000.0Z":   "(modifyTimestamp>=20261121093000.0Z)",
		"":                       "",
		"usn:-1":                 "",
		"usn:1)(uid=*":           "",
		"ts:2026)(objectClass=*": "",
		"other:1":                "",
	} {
		got, ok := cursorTerm(cursor)
		if got != want || ok != (want != "") {
			t.Errorf("cursorTerm(%q) = %q, %v; want %q", cursor, got, ok, want)
		}
	}
	entry := func(usn, ts string) *goldap.Entry {
		return goldap.NewEntry("uid=x,dc=example,dc=test", map[string][]string{attrUSNChanged: {usn}, attrModifyTimestamp: {ts}})
	}
	ad := []*goldap.Entry{entry("120", "20261121093000.0Z"), entry("180", "20261121080000.0Z")}
	other := []*goldap.Entry{goldap.NewEntry("uid=x", map[string][]string{attrModifyTimestamp: {"20261121093000Z"}}),
		goldap.NewEntry("uid=y", map[string][]string{attrModifyTimestamp: {"20261121100000Z"}})}
	for _, test := range []struct {
		name    string
		cursor  string
		entries []*goldap.Entry
		want    string
	}{
		{"first Active Directory run", "", ad, "usn:180"},
		{"Active Directory moves on", "usn:150", ad, "usn:180"},
		{"Active Directory nothing newer", "usn:200", ad, ""},
		{"first run elsewhere", "", other, "ts:20261121100000Z"},
		{"elsewhere moves on", "ts:20261121090000Z", other, "ts:20261121100000Z"},
		{"nothing changed", "usn:180", nil, ""},
		{"no marks at all", "", []*goldap.Entry{goldap.NewEntry("uid=z", nil)}, ""},
	} {
		if got := nextCursor(test.cursor, test.entries); got != test.want {
			t.Errorf("%s: nextCursor = %q, want %q", test.name, got, test.want)
		}
	}
}

// TestPlanSync checks what a sync does to each account the connection signed in.
func TestPlanSync(t *testing.T) {
	id := func() uuid.UUID { return uuid.New() }
	alice := linkedAccount{userID: id(), dns: []string{dnKey("uid=alice,ou=People,dc=example,dc=test")}, emails: []string{"alice@example.test"}, status: "active"}
	bob := linkedAccount{userID: id(), dns: []string{dnKey("uid=bob,dc=example,dc=test")}, emails: []string{"bob@example.test"}, status: "active"}
	carol := linkedAccount{userID: id(), dns: []string{dnKey("uid=carol,dc=example,dc=test")}, emails: []string{"carol@example.test"}, status: "active"}
	owner := linkedAccount{userID: id(), dns: []string{dnKey("uid=root,dc=example,dc=test")}, emails: []string{"root@example.test"}, status: "active", owner: true}
	back := linkedAccount{userID: id(), dns: []string{dnKey("uid=dan,dc=example,dc=test")}, emails: []string{"dan@example.test"}, status: "suspended", suspensionSource: "ldap"}
	held := linkedAccount{userID: id(), dns: []string{dnKey("uid=eve,dc=example,dc=test")}, emails: []string{"eve@example.test"}, status: "suspended", suspensionSource: "manual"}
	moved := linkedAccount{userID: id(), dns: []string{dnKey("uid=fay,ou=Old,dc=example,dc=test")}, emails: []string{"fay@example.test"}, status: "active"}
	person := func(dn, email string, disabled bool) dirPerson {
		return dirPerson{dn: dn, key: dnKey(dn), email: email, disabled: disabled}
	}
	people := []dirPerson{
		person("UID=Alice, OU=people, DC=example, DC=test", "alice@example.test", false),
		person("uid=bob,dc=example,dc=test", "bob@example.test", true),
		person("uid=root,dc=example,dc=test", "root@example.test", true),
		person("uid=dan,dc=example,dc=test", "dan@example.test", false),
		person("uid=eve,dc=example,dc=test", "eve@example.test", false),
		person("uid=fay,ou=New,dc=example,dc=test", "fay@example.test", false),
	}
	accounts := []linkedAccount{alice, bob, carol, owner, back, held, moved}
	kinds := func(plan []syncAction) map[uuid.UUID]string {
		out := map[uuid.UUID]string{}
		for _, a := range plan {
			out[a.account.userID] = a.kind + "/" + a.cause
		}
		return out
	}
	full := kinds(planSync(people, accounts, true))
	for name, test := range map[string]struct {
		id   uuid.UUID
		want string
	}{
		"enabled, DN spelled otherwise": {alice.userID, syncRefresh + "/"},
		"disabled":                      {bob.userID, syncSuspend + "/" + causeDisabled},
		"no longer listed":              {carol.userID, syncSuspend + "/" + causeRemoved},
		"owner disabled":                {owner.userID, syncKeep + "/" + causeDisabled},
		"enabled again":                 {back.userID, syncReactivate + "/"},
		"suspended by an administrator": {held.userID, ""},
		"moved, found by address":       {moved.userID, syncRefresh + "/"},
	} {
		if got := full[test.id]; got != test.want {
			t.Errorf("full run, %s: %q, want %q", name, got, test.want)
		}
	}
	incremental := kinds(planSync(people[:2], accounts, false))
	if incremental[carol.userID] != "" || incremental[bob.userID] != syncSuspend+"/"+causeDisabled || len(incremental) != 2 {
		t.Errorf("incremental run: %v; want only alice refreshed and bob suspended, nobody suspended for being unlisted", incremental)
	}
	twins := []dirPerson{person("uid=a1,dc=example,dc=test", "shared@example.test", false), person("uid=a2,dc=example,dc=test", "shared@example.test", false)}
	sharer := linkedAccount{userID: id(), dns: []string{dnKey("uid=gone,dc=example,dc=test")}, emails: []string{"shared@example.test"}, status: "active"}
	if got := kinds(planSync(twins, []linkedAccount{sharer}, true))[sharer.userID]; got != syncSuspend+"/"+causeRemoved {
		t.Errorf("an address two entries share: %q, want no match by it", got)
	}
}

// TestJudge checks that a full run whose answer looks incomplete is refused.
func TestJudge(t *testing.T) {
	n := func(v int32) *int32 { return &v }
	plan := func(refresh, gone, disabled int) []syncAction {
		var p []syncAction
		for range refresh {
			p = append(p, syncAction{kind: syncRefresh})
		}
		for range gone {
			p = append(p, syncAction{kind: syncSuspend, cause: causeRemoved})
		}
		for range disabled {
			p = append(p, syncAction{kind: syncSuspend, cause: causeDisabled})
		}
		return p
	}
	for _, test := range []struct {
		name     string
		found    int
		previous *int32
		plan     []syncAction
		want     error
	}{
		{"empty, with people signed in", 0, nil, plan(0, 3, 0), ErrSyncEmptyResult},
		{"empty, after finding some", 0, n(2), nil, ErrSyncEmptyResult},
		{"empty, never had anyone", 0, nil, nil, nil},
		{"under half the last run", 40, n(100), plan(40, 0, 0), ErrSyncPeopleDropped},
		{"half the last run", 50, n(100), plan(50, 0, 0), nil},
		{"a small directory shrinking", 2, n(9), plan(2, 1, 0), nil},
		{"most accounts gone", 30, nil, plan(2, 3, 0), ErrSyncPeopleDropped},
		{"a few accounts gone", 30, nil, plan(8, 2, 0), nil},
		{"many disabled, all listed", 30, n(30), plan(1, 0, 9), nil},
		{"one of two gone", 1, nil, plan(1, 1, 0), nil},
	} {
		if err := judge(test.found, test.previous, test.plan); !errors.Is(err, test.want) && (err != nil || test.want != nil) {
			t.Errorf("%s: %v, want %v", test.name, err, test.want)
		}
	}
}
