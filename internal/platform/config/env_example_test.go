package config

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// envLine matches a variable in .env.example, set or commented out: KEY=… or # KEY=….
var envLine = regexp.MustCompile(`^#?\s*([A-Z][A-Z0-9_]*)=`)

// TestEnvExampleListsEveryVariable checks that .env.example names exactly the
// variables Config reads, so a new setting can't ship undocumented and a removed
// one can't linger.
func TestEnvExampleListsEveryVariable(t *testing.T) {
	want := map[string]bool{}
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		if key := typ.Field(i).Tag.Get("envconfig"); key != "" {
			want[key] = true
		}
	}
	if len(want) < 50 {
		t.Fatalf("Config has only %d envconfig tags; the test is probably broken", len(want))
	}

	f, err := os.Open(filepath.Join("..", "..", "..", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := envLine.FindStringSubmatch(sc.Text()); m != nil {
			got[m[1]] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	if missing := diff(want, got); len(missing) > 0 {
		t.Errorf(".env.example is missing %v: add each with its default and a one-line comment", missing)
	}
	if unknown := diff(got, want); len(unknown) > 0 {
		t.Errorf(".env.example lists %v, which Config doesn't read: remove them", unknown)
	}
}

// diff returns the keys of a that aren't in b, sorted.
func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
