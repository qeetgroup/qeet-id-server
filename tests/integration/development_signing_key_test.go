//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// TestADevelopmentInstanceWithoutAKeyNeverMakesOnePerStart pins what an
// instance started with SERVICE_ENV=dev and no JWT_SIGNING_KEY does with the
// shared key registry. It makes a key only for a database that has none, and
// instances starting together agree on that one key, so one's token verifies
// on another. Restarts add no key. An instance whose vault key can't open the
// active key refuses, and the active key stays.
func TestADevelopmentInstanceWithoutAKeyNeverMakesOnePerStart(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	box := testEnvelope(t)

	// Start from a database with no active key: park the active one (if any)
	// as a candidate, and put it back afterwards.
	before := keyKIDs(t, ctx)
	var parked string
	if err := testPool.QueryRow(ctx,
		`UPDATE platform.jwt_signing_keys SET state = 'candidate' WHERE state = 'active' RETURNING kid`).Scan(&parked); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("park the active key: %v", err)
	}
	t.Cleanup(func() {
		for kid := range keyKIDs(t, ctx) {
			if !before[kid] {
				if _, err := testPool.Exec(ctx, `DELETE FROM platform.jwt_signing_keys WHERE kid = $1`, kid); err != nil {
					t.Errorf("remove test key: %v", err)
				}
			}
		}
		if parked != "" {
			if _, err := testPool.Exec(ctx, `UPDATE platform.jwt_signing_keys SET state = 'active' WHERE kid = $1`, parked); err != nil {
				t.Errorf("restore the active key: %v", err)
			}
		}
	})

	// start is what bootstrap does for such an instance.
	start := func(_ *testing.T, box *envelope.Cipher) (*tokens.Issuer, bool, error) {
		registry, err := tokens.NewSigningKeyRegistry(testPool, box)
		if err != nil {
			return nil, false, err
		}
		generated, err := registry.EnsureDevelopmentKey(ctx)
		if err != nil {
			return nil, generated, err
		}
		issuer, err := registry.NewIssuer(ctx, "dev-key-test", "dev-key-test", 15*time.Minute, time.Hour)
		return issuer, generated, err
	}

	t.Run("instances starting together on a database with no key agree on one", func(t *testing.T) {
		const instances = 4
		issuers := make([]*tokens.Issuer, instances)
		generated := make([]bool, instances)
		errs := make([]error, instances)
		var wait sync.WaitGroup
		for i := range instances {
			wait.Add(1)
			go func() {
				defer wait.Done()
				issuers[i], generated[i], errs[i] = start(t, box)
			}()
		}
		wait.Wait()
		made := 0
		for i := range instances {
			if errs[i] != nil {
				t.Fatalf("instance %d: %v", i, errs[i])
			}
			if generated[i] {
				made++
			}
			if issuers[i].KID() != issuers[0].KID() {
				t.Fatalf("instances sign with %s and %s", issuers[0].KID(), issuers[i].KID())
			}
		}
		if made != 1 {
			t.Fatalf("%d instances made a key, want 1", made)
		}
		token, _, err := issuers[1].IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := issuers[3].VerifyAccess(token); err != nil {
			t.Fatalf("one instance's token is refused by another: %v", err)
		}
	})

	t.Run("restarts add no key and keep the one in use", func(t *testing.T) {
		first, _, err := start(t, box)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		keys := len(keyKIDs(t, ctx))
		for range 10 {
			again, generated, err := start(t, box)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			if generated || again.KID() != first.KID() {
				t.Fatalf("a restart made a key (%v) or signs with %s, not %s", generated, again.KID(), first.KID())
			}
		}
		if n := len(keyKIDs(t, ctx)); n != keys {
			t.Fatalf("ten restarts took the registry from %d keys to %d", keys, n)
		}
	})

	t.Run("an instance whose vault key can't open the active key refuses, and the key stays", func(t *testing.T) {
		running, _, err := start(t, box)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		other, err := envelope.New([]byte("another-vault-key-for-this-test!"))
		if err != nil {
			t.Fatalf("other vault key: %v", err)
		}
		if _, _, err := start(t, other); !errors.Is(err, tokens.ErrActiveKeySealedElsewhere) {
			t.Fatalf("start with another vault key: err = %v, want %v", err, tokens.ErrActiveKeySealedElsewhere)
		}
		var active string
		if err := testPool.QueryRow(ctx, `SELECT kid FROM platform.jwt_signing_keys WHERE state = 'active'`).Scan(&active); err != nil {
			t.Fatalf("read active key: %v", err)
		}
		if active != running.KID() {
			t.Fatalf("the refused instance replaced the active key %s with %s", running.KID(), active)
		}
	})

	t.Run("an instance that can't refresh the keyring stops being ready", func(t *testing.T) {
		issuer, _, err := start(t, box)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		other, err := envelope.New([]byte("another-vault-key-for-this-test!"))
		if err != nil {
			t.Fatalf("other vault key: %v", err)
		}
		stale, err := tokens.NewSigningKeyRegistry(testPool, other)
		if err != nil {
			t.Fatalf("registry: %v", err)
		}
		for i := 1; i <= tokens.SyncFailuresUntilNotReady; i++ {
			if err := stale.Sync(ctx, issuer); err == nil {
				t.Fatal("a registry with another vault key refreshed the keyring")
			}
			ready := stale.Ready(ctx)
			if i < tokens.SyncFailuresUntilNotReady && ready != nil {
				t.Fatalf("not ready after %d failed refresh(es): %v", i, ready)
			}
			if i == tokens.SyncFailuresUntilNotReady && ready == nil {
				t.Fatalf("still ready after %d failed refreshes in a row", i)
			}
		}
	})
}

// keyKIDs lists every kid in the signing key registry.
func keyKIDs(t *testing.T, ctx context.Context) map[string]bool {
	t.Helper()
	rows, err := testPool.Query(ctx, `SELECT kid FROM platform.jwt_signing_keys`)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var kid string
		if err := rows.Scan(&kid); err != nil {
			t.Fatalf("scan kid: %v", err)
		}
		out[kid] = true
	}
	return out
}
