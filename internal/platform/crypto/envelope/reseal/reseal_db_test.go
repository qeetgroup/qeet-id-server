//go:build integration

package reseal

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

var (
	oldKey   = bytes.Repeat([]byte{1}, 32)
	newKey   = bytes.Repeat([]byte{2}, 32)
	strayKey = bytes.Repeat([]byte{3}, 32)
)

func mustCipher(t *testing.T, current []byte, previous ...[]byte) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// scratchTable creates a table of sealed values keyed by id and returns the
// column over it.
func scratchTable(t *testing.T) Column {
	t.Helper()
	table := "platform." + strings.ReplaceAll(dbtest.Unique("reseal"), "-", "_")
	if _, err := dbtest.Owner(t).Exec(dbtest.Context(t), `CREATE TABLE `+table+` (
		id uuid PRIMARY KEY, organization_id uuid NOT NULL, name text NOT NULL, ct bytea, nonce bytea)`); err != nil {
		t.Fatal(err)
	}
	return Column{Table: table, Key: []string{"id"}, Ciphertext: "ct", Nonce: "nonce",
		Organization: "organization_id", Purpose: "secret", Resource: "name"}
}

// put stores a value sealed as ct and nonce under organization and name.
func put(t *testing.T, c Column, organization uuid.UUID, name string, ct, nonce []byte) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t),
		`INSERT INTO `+c.Table+` (id, organization_id, name, ct, nonce) VALUES ($1, $2, $3, $4, $5)`,
		id, organization, name, ct, nonce); err != nil {
		t.Fatal(err)
	}
	return id
}

// stored returns the value stored for id.
func stored(t *testing.T, c Column, id uuid.UUID) ([]byte, []byte) {
	t.Helper()
	var ct, nonce []byte
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t),
		`SELECT ct, nonce FROM `+c.Table+` WHERE id = $1`, id).Scan(&ct, &nonce); err != nil {
		t.Fatal(err)
	}
	return ct, nonce
}

func count(t *testing.T, box *envelope.Cipher, c Column) int64 {
	t.Helper()
	n, err := Count(dbtest.Context(t), dbtest.Pool(t), box, []Column{c})
	if err != nil {
		t.Fatal(err)
	}
	return n[0]
}

// TestRunMovesValuesToTheCurrentKey seals values with a previous key, the
// current key, a key that is not configured and the wrong context, then checks that a run in small batches moves exactly the readable
// ones to the current key, leaves the rest, and that running it again changes
// nothing.
func TestRunMovesValuesToTheCurrentKey(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	c := scratchTable(t)
	organization := uuid.New()
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)

	want := map[uuid.UUID]string{}
	for i := range 5 {
		name := fmt.Sprintf("old-%d", i)
		ct, nonce, err := before.Seal(organization, "secret", name, []byte("value of "+name))
		if err != nil {
			t.Fatal(err)
		}
		want[put(t, c, organization, name, ct, nonce)] = "value of " + name
	}

	currentCT, currentNonce, _ := after.Seal(organization, "secret", "current", []byte("current value"))
	current := put(t, c, organization, "current", currentCT, currentNonce)
	strayCT, strayNonce, _ := mustCipher(t, strayKey).Seal(organization, "secret", "stray", []byte("stray"))
	stray := put(t, c, organization, "stray", strayCT, strayNonce)
	elsewhereCT, elsewhereNonce, _ := before.Seal(organization, "secret", "other-name", []byte("moved"))
	put(t, c, organization, "elsewhere", elsewhereCT, elsewhereNonce)
	put(t, c, organization, "empty", nil, nil)

	if n := count(t, after, c); n != 7 {
		t.Fatalf("before the run %d values are on old keys, want 7", n)
	}
	res, err := Run(ctx, pool, after, []Column{c}, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resealed != 5 || res.Unreadable != 2 || !res.Finished {
		t.Fatalf("run = %+v, want 5 resealed, 2 unreadable, finished", res)
	}
	if n := count(t, after, c); n != 2 {
		t.Errorf("after the run %d values are on old keys, want the 2 unreadable", n)
	}

	newOnly := mustCipher(t, newKey)
	for id, plain := range want {
		ct, nonce := stored(t, c, id)
		if !newOnly.IsCurrent(ct) {
			t.Errorf("%s was not moved to the current key", plain)
		}
		var name string
		if err := pool.QueryRow(ctx, `SELECT name FROM `+c.Table+` WHERE id = $1`, id).Scan(&name); err != nil {
			t.Fatal(err)
		}
		got, err := newOnly.Open(organization, "secret", name, ct, nonce)
		if err != nil || string(got) != plain {
			t.Errorf("%s opens to %q, %v once the old key is removed", name, got, err)
		}
	}
	if ct, _ := stored(t, c, current); !bytes.Equal(ct, currentCT) {
		t.Error("a value already on the current key was rewritten")
	}
	if ct, _ := stored(t, c, stray); !bytes.Equal(ct, strayCT) {
		t.Error("a value no configured key opens was rewritten")
	}

	again, err := Run(ctx, pool, after, []Column{c}, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if again.Resealed != 0 || again.Unreadable != 2 {
		t.Errorf("second run = %+v, want nothing resealed", again)
	}
}

// TestRunPagesACompositeKey checks a column keyed by two columns whose organization
// is read from a column's text, as the idempotency keys are.
func TestRunPagesACompositeKey(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	table := "platform." + strings.ReplaceAll(dbtest.Unique("reseal_pair"), "-", "_")
	if _, err := dbtest.Owner(t).Exec(ctx, `CREATE TABLE `+table+` (
		scope text, key text, body bytea, body_nonce bytea, PRIMARY KEY (scope, key))`); err != nil {
		t.Fatal(err)
	}
	organization := uuid.New()
	c := Column{Table: table, Key: []string{"scope", "key"}, Ciphertext: "body", Nonce: "body_nonce",
		Organization: "scope", OrganizationOf: func(scope string) uuid.UUID {
			id, _ := uuid.Parse(strings.SplitN(scope, "|", 2)[0])
			return id
		}, Purpose: "pair", Resource: "scope || '|' || key"}
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)
	for _, scope := range []string{"a", "b"} {
		for i := range 3 {
			s, k := organization.String()+"|"+scope, fmt.Sprint(i)
			ct, nonce, err := before.Seal(organization, "pair", s+"|"+k, []byte("answer"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO `+table+` VALUES ($1, $2, $3, $4)`, s, k, ct, nonce); err != nil {
				t.Fatal(err)
			}
		}
	}
	res, err := Run(ctx, pool, after, []Column{c}, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resealed != 6 || res.Unreadable != 0 {
		t.Errorf("run = %+v, want all 6 resealed", res)
	}
	if n := count(t, after, c); n != 0 {
		t.Errorf("%d values left on old keys", n)
	}
}

// TestRunWithTheKeyAsResource checks a column whose context's resource is its
// key, as most are: the two must not be confused when ordering the rows.
func TestRunWithTheKeyAsResource(t *testing.T) {
	c := scratchTable(t)
	c.Resource = "id"
	organization, id := uuid.New(), uuid.New()
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)
	ct, nonce, _ := before.Seal(organization, "secret", id.String(), []byte("value"))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO `+c.Table+` (id, organization_id, name, ct, nonce) VALUES ($1, $2, 'n', $3, $4)`,
		id, organization, ct, nonce); err != nil {
		t.Fatal(err)
	}
	res, err := Run(dbtest.Context(t), dbtest.Pool(t), after, []Column{c}, 10, time.Minute)
	if err != nil || res.Resealed != 1 {
		t.Fatalf("run = %+v, %v; want the value resealed", res, err)
	}
}

// TestStoreKeepsANewerValue checks that a value the application replaced
// after the job read it is not overwritten with the old one.
func TestStoreKeepsANewerValue(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	c := scratchTable(t)
	organization := uuid.New()
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)
	ct, nonce, _ := before.Seal(organization, "secret", "rotated", []byte("old value"))
	id := put(t, c, organization, "rotated", ct, nonce)

	rows, err := c.next(ctx, pool, after.CurrentPrefix(), nil, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("next = %d rows, %v", len(rows), err)
	}
	newer, newerNonce, _ := after.Seal(organization, "secret", "rotated", []byte("new value"))
	if _, err := pool.Exec(ctx, `UPDATE `+c.Table+` SET ct = $2, nonce = $3 WHERE id = $1`, id, newer, newerNonce); err != nil {
		t.Fatal(err)
	}
	organizationID, plain, err := c.open(after, rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if replaced, err := c.store(ctx, pool, after, rows[0], organizationID, plain); err != nil || replaced {
		t.Fatalf("store over a newer value = %v, %v; want it left alone", replaced, err)
	}
	got, gotNonce := stored(t, c, id)
	if plain, err := after.Open(organization, "secret", "rotated", got, gotNonce); err != nil || string(plain) != "new value" {
		t.Errorf("stored value is %q, %v; want the application's", plain, err)
	}
}

// TestRunStopsAtItsBudget checks that a run out of time stops, reports it is
// unfinished, and leaves the rest for the next run.
func TestRunStopsAtItsBudget(t *testing.T) {
	c := scratchTable(t)
	organization := uuid.New()
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)
	ct, nonce, _ := before.Seal(organization, "secret", "waiting", []byte("value"))
	put(t, c, organization, "waiting", ct, nonce)
	res, err := Run(dbtest.Context(t), dbtest.Pool(t), after, []Column{c}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Finished || res.Resealed != 0 {
		t.Errorf("run with no time = %+v, want unfinished", res)
	}
	if n := count(t, after, c); n != 1 {
		t.Errorf("%d values on old keys, want the one left for the next run", n)
	}
}

// TestCollectorReportsValuesOnOldKeys checks the gauge an operator watches to
// know when a previous key can be removed.
func TestCollectorReportsValuesOnOldKeys(t *testing.T) {
	c := scratchTable(t)
	organization := uuid.New()
	before, after := mustCipher(t, oldKey), mustCipher(t, newKey, oldKey)
	for i := range 3 {
		ct, nonce, _ := before.Seal(organization, "secret", fmt.Sprint(i), []byte("value"))
		put(t, c, organization, fmt.Sprint(i), ct, nonce)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(Collector(dbtest.Pool(t), after, []Column{c}))
	gauge := func() float64 {
		families, err := reg.Gather()
		if err != nil || len(families) != 1 || len(families[0].GetMetric()) != 1 {
			t.Fatalf("gather = %v, %v", families, err)
		}
		m := families[0].GetMetric()[0]
		if families[0].GetName() != "envelope_rows_on_old_keys" || m.GetLabel()[0].GetValue() != c.Name() {
			t.Fatalf("metric %s{%v}", families[0].GetName(), m.GetLabel())
		}
		return m.GetGauge().GetValue()
	}
	if v := gauge(); v != 3 {
		t.Errorf("gauge = %v before the run, want 3", v)
	}
	if _, err := Run(dbtest.Context(t), dbtest.Pool(t), after, []Column{c}, 10, time.Minute); err != nil {
		t.Fatal(err)
	}
	if v := gauge(); v != 0 {
		t.Errorf("gauge = %v after the run, want 0", v)
	}
}
