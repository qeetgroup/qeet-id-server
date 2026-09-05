package rbac

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestBackfillMigrationMatchesBuiltinPermissions pins migration 0105's
// compatibility scope list to builtinPermissionDefinitions.
//
// 0105 widens pre-enforcement machine credentials to the scopes they already
// had in practice. If a permission is added here but not there, credentials
// migrated by 0105 silently lack it; if one is removed here but left there,
// ValidateMachineScopes rejects a credential the migration itself wrote.
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
