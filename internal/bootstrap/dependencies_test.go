package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestRunRefusesToStartWhenTheCatalogueCannotBeSeeded checks that start-up
// fails, naming the catalogue, when one can't be seeded after its retries,
// rather than run with an empty permission catalogue or no plans, and that a
// seed failing only at first is retried and start-up goes on.
func TestRunRefusesToStartWhenTheCatalogueCannotBeSeeded(t *testing.T) {
	seedRetryDelay = time.Millisecond
	t.Cleanup(func() { seedRetryDelay = 2 * time.Second })
	down := errors.New("database starting up")
	calls := map[string]int{}
	failing := func(name string, failures int) namedSeeder {
		return namedSeeder{name: name, seed: func(context.Context) error {
			calls[name]++
			if calls[name] <= failures {
				return down
			}
			return nil
		}}
	}

	err := seedCatalogues(context.Background(), []namedSeeder{failing("billing plans", 1), failing("permission catalogue", seedAttempts)})
	if !errors.Is(err, down) || !strings.Contains(err.Error(), "permission catalogue") {
		t.Errorf("a catalogue failing every attempt: %v, want start-up refused naming it", err)
	}
	if calls["permission catalogue"] != seedAttempts {
		t.Errorf("the failing catalogue was tried %d times, want %d", calls["permission catalogue"], seedAttempts)
	}
	if calls["billing plans"] != 2 {
		t.Errorf("a catalogue failing once was tried %d times, want 2", calls["billing plans"])
	}

	clear(calls)
	if err := seedCatalogues(context.Background(), []namedSeeder{failing("billing plans", 0), failing("permission catalogue", seedAttempts-1)}); err != nil {
		t.Errorf("catalogues that seed within their attempts: %v, want start-up to go on", err)
	}
}
