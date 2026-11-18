package migrations

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestLatestIsTheNewestEmbeddedMigration(t *testing.T) {
	latest, err := Latest()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := sqlFiles.ReadDir(".")
	var newest string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") && e.Name() > newest {
			newest = e.Name()
		}
	}
	if !strings.HasPrefix(newest, fmt.Sprintf("%04d_", latest)) {
		t.Fatalf("Latest() = %d, newest file %s", latest, newest)
	}
}

// TestCheckStatus checks that this build runs on a database at or behind its
// latest migration and refuses a newer or dirty one, naming the recovery step.
func TestCheckStatus(t *testing.T) {
	for _, st := range []Status{{Database: 0, Latest: 147}, {Database: 120, Latest: 147}, {Database: 147, Latest: 147}} {
		if err := checkStatus(st); err != nil {
			t.Errorf("%+v refused: %v", st, err)
		}
	}
	err := checkStatus(Status{Database: 150, Latest: 147})
	if !errors.Is(err, ErrSchemaNewer) || !strings.Contains(err.Error(), "migration 150") ||
		!strings.Contains(err.Error(), "roll forward") || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("newer schema: %v", err)
	}
	err = checkStatus(Status{Database: 140, Dirty: true, Latest: 147})
	if !errors.Is(err, ErrSchemaDirty) || !strings.Contains(err.Error(), "database-operations.md") {
		t.Fatalf("dirty schema: %v", err)
	}
}

// TestChanged checks that a database is told from this build by the files
// recorded for the migrations it has applied, and by those only.
func TestChanged(t *testing.T) {
	ups := []upMigration{{version: 1, name: "0001_a.up.sql", checksum: "aa"}, {version: 2, name: "0002_b.up.sql", checksum: "bb"}, {version: 3, name: "0003_c.up.sql", checksum: "cc"}}
	for name, c := range map[string]struct {
		recorded map[uint]string
		through  uint
		want     string
	}{
		"every applied file as recorded":               {map[uint]string{1: "aa", 2: "bb", 3: "cc"}, 3, ""},
		"nothing applied":                              {nil, 0, ""},
		"a file edited before it is applied":           {map[uint]string{1: "aa", 2: "bb", 3: "old"}, 2, ""},
		"an applied file edited":                       {map[uint]string{1: "aa", 2: "old", 3: "cc"}, 3, "0002_b.up.sql"},
		"an applied migration with no record":          {map[uint]string{1: "aa", 3: "cc"}, 3, "0002_b.up.sql"},
		"no records":                                   {nil, 2, "0001_a.up.sql"},
		"an applied migration the build has no more":   {map[uint]string{1: "aa", 2: "bb", 4: "dd", 3: "cc"}, 4, "migration 4"},
		"at a migration the build has not, unrecorded": {map[uint]string{1: "aa", 2: "bb", 3: "cc"}, 4, "migration 4"},
	} {
		got := changed(ups, c.recorded, c.through)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want it to name %q", name, got, c.want)
		}
	}
}

// TestUpMigrations checks that the build's migrations are read oldest first,
// each with the checksum of its own contents.
func TestUpMigrations(t *testing.T) {
	ups, err := upMigrations()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, up := range ups {
		if i > 0 && up.version <= ups[i-1].version {
			t.Errorf("%s comes after %s", up.name, ups[i-1].name)
		}
		if len(up.checksum) != 64 || seen[up.checksum] {
			t.Errorf("%s has checksum %q, want its own SHA-256", up.name, up.checksum)
		}
		seen[up.checksum] = true
	}
	if latest, err := Latest(); err != nil || len(ups) == 0 || ups[len(ups)-1].version != latest {
		t.Errorf("Latest() = %d, %v; the last of %d migrations read", latest, err, len(ups))
	}
}

// TestSchemaChangedSaysWhatToDo checks that the refusal of a database built
// from other files names what differs and the way out.
func TestSchemaChangedSaysWhatToDo(t *testing.T) {
	err := &SchemaError{Status: Status{Database: 12, Latest: 12}, Err: ErrSchemaChanged, Changed: "0005_organization.up.sql differs"}
	for _, want := range []string{"migration 12", "0005_organization.up.sql differs", "make db-reset", "new migration"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q, want it to say %q", err.Error(), want)
		}
	}
}

var (
	createIndex = regexp.MustCompile(`(?is)\bcreate\s+(unique\s+)?index\s+(concurrently\s+)?(if\s+not\s+exists\s+)?\S+\s+on\s+(only\s+)?([a-z0-9_."]+)`)
	createTable = regexp.MustCompile(`(?is)\bcreate\s+table\s+(if\s+not\s+exists\s+)?([a-z0-9_."]+)`)
	lineComment = regexp.MustCompile(`--[^\n]*`)
)

// TestNewIndexesDontLockTheirTable checks that a migration adds an index to a
// table that already exists with CREATE INDEX CONCURRENTLY, alone in its file:
// a plain CREATE INDEX blocks every write to the table while it builds, and a
// concurrent build can't run beside other statements. An index on a table its
// own file creates, as in the baseline, locks nothing.
func TestNewIndexesDontLockTheirTable(t *testing.T) {
	names, err := fs.Glob(sqlFiles, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		raw, err := fs.ReadFile(sqlFiles, name)
		if err != nil {
			t.Fatal(err)
		}
		sql := lineComment.ReplaceAllString(string(raw), "")
		created := map[string]bool{}
		for _, c := range createTable.FindAllStringSubmatch(sql, -1) {
			created[strings.ToLower(c[2])] = true
		}
		statements := 0
		for _, s := range strings.Split(sql, ";") {
			if strings.TrimSpace(s) != "" {
				statements++
			}
		}
		for _, idx := range createIndex.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(idx[5])
			switch {
			case created[table]:
			case idx[2] == "":
				t.Errorf("%s indexes %s without CONCURRENTLY; build it with CREATE INDEX CONCURRENTLY", name, table)
			case statements != 1:
				t.Errorf("%s builds an index CONCURRENTLY beside other statements; give it a file of its own", name)
			}
		}
	}
}

// TestIndexRuleReadsMigrations checks the rule's patterns against the forms a
// migration writes.
func TestIndexRuleReadsMigrations(t *testing.T) {
	for sql, table := range map[string]string{
		"CREATE INDEX idx_a ON auth.sessions (user_id)":                                     "auth.sessions",
		"create unique index concurrently if not exists uq_b on organization.groups (name)": "organization.groups",
		"CREATE INDEX idx_c ON ONLY account.users (email)":                                  `account.users`,
	} {
		m := createIndex.FindStringSubmatch(sql)
		if m == nil || !strings.EqualFold(m[5], table) {
			t.Errorf("%q: read %v, want the table %s", sql, m, table)
		}
	}
}

// LockTimeout lets the external tests shorten how long a migration waits for
// a busy table.
var LockTimeout = &lockTimeout

// Source lets the external tests give the runner other migration files than
// the build's.
var Source = &source
