package rbac

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestBackfillMigrationMatchesBuiltinPermissions checks that migration 0105's
// machine-scope backfill, with the permissions 0207 split from user.write and
// tenant.write and gave every holder of those, lists exactly
// builtinPermissionDefinitions. Otherwise backfilled credentials lack a
// permission, or ValidateMachineScopes rejects a scope a migration wrote.
func TestBackfillMigrationMatchesBuiltinPermissions(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
	migration := filepath.Join(repoRoot,
		"internal", "platform", "database", "migrations", "0105_machine_scope_backfill.up.sql")

	raw, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read backfill migration: %v", err)
	}

	inMigration := scopeLiteralsIn(string(raw))
	split, err := os.ReadFile(filepath.Join(filepath.Dir(migration), "0207_finer_permissions.up.sql"))
	if err != nil {
		t.Fatalf("read the permission split migration: %v", err)
	}
	inMigration = append(inMigration, permissionsInsertedBy(string(split))...)
	inCode := make([]string, 0, len(builtinPermissionDefinitions))
	for _, permission := range builtinPermissionDefinitions {
		inCode = append(inCode, permission.Key)
	}
	sort.Strings(inMigration)
	sort.Strings(inCode)

	if strings.Join(inMigration, ",") != strings.Join(inCode, ",") {
		t.Fatalf("0105 scope list has drifted from builtinPermissionDefinitions\nmigration: %v\ncode:      %v",
			inMigration, inCode)
	}
}

// scopeLiteralsIn pulls the single-quoted permission keys out of the migration's
// builtin_scopes array, ignoring prose in the surrounding comments.
func scopeLiteralsIn(sql string) []string {
	start := strings.Index(sql, "builtin_scopes TEXT[] := ARRAY[")
	if start < 0 {
		return nil
	}
	end := strings.Index(sql[start:], "];")
	if end < 0 {
		return nil
	}
	body := sql[start : start+end]

	var scopes []string
	for _, part := range strings.Split(body, "'") {
		// Permission keys are the only "<word>.<word>" literals in the array.
		if strings.Count(part, ".") == 1 && !strings.ContainsAny(part, " ,[]\n") && part != "" {
			scopes = append(scopes, part)
		}
	}
	return scopes
}

// permissionsInsertedBy pulls the keys out of a migration's INSERT INTO
// rbac.permissions: the first literal of each row.
func permissionsInsertedBy(sql string) []string {
	start := strings.Index(sql, "INSERT INTO rbac.permissions")
	if start < 0 {
		return nil
	}
	end := strings.Index(sql[start:], ";")
	var keys []string
	for _, line := range strings.Split(sql[start:start+end], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "('") {
			continue
		}
		if key, _, ok := strings.Cut(line[2:], "'"); ok {
			keys = append(keys, key)
		}
	}
	return keys
}
