package migrations

import (
	"errors"
	"fmt"
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
