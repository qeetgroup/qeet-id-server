package migrations

import (
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// firstGuardedMigration is the first migration held to the index rule below;
// the ones before it were applied without it.
const firstGuardedMigration = 175

var (
	createIndex   = regexp.MustCompile(`(?is)\bcreate\s+(unique\s+)?index\s+(concurrently\s+)?(if\s+not\s+exists\s+)?\S+\s+on\s+(only\s+)?([a-z0-9_."]+)`)
	createTable   = regexp.MustCompile(`(?is)\bcreate\s+table\s+(if\s+not\s+exists\s+)?([a-z0-9_."]+)`)
	lineComment   = regexp.MustCompile(`--[^\n]*`)
	migrationName = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)
)

// TestNewIndexesDontLockTheirTable checks that a migration adds an index to a
// table that already exists with CREATE INDEX CONCURRENTLY, alone in its file:
// a plain CREATE INDEX blocks every write to the table while it builds, and a
// concurrent build can't run beside other statements.
func TestNewIndexesDontLockTheirTable(t *testing.T) {
	names, err := fs.Glob(sqlFiles, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		m := migrationName.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		if n, _ := strconv.Atoi(m[1]); n < firstGuardedMigration {
			continue
		}
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
		"CREATE INDEX idx_a ON auth.sessions (user_id)":                               "auth.sessions",
		"create unique index concurrently if not exists uq_b on tenant.groups (name)": "tenant.groups",
		"CREATE INDEX idx_c ON ONLY \"user\".users (email)":                           `"user".users`,
	} {
		m := createIndex.FindStringSubmatch(sql)
		if m == nil || !strings.EqualFold(m[5], table) {
			t.Errorf("%q: read %v, want the table %s", sql, m, table)
		}
	}
}
