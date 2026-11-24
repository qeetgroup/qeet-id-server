package audit

import (
	"encoding/json"
	"testing"
)

func TestNormaliseMetadata_RoundTripCanonical(t *testing.T) {
	// Simulate what Postgres returns for JSONB: same logical structure,
	// possibly with whitespace.
	cases := []struct {
		in   string
		want string
	}{
		{`{"a":1,"b":2}`, `{"a":1,"b":2}`},
		{`{"a": 1, "b": 2}`, `{"a":1,"b":2}`},          // spaces stripped
		{`{"b":2,"a":1}`, `{"a":1,"b":2}`},             // keys sorted
		{``, `{}`},                                     // empty becomes {}
		{`null`, `{}`},                                 // null becomes {}
		{`{"n":{"a":1,"b":2}}`, `{"n":{"a":1,"b":2}}`}, // nested keys sorted
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := normaliseMetadata([]byte(tc.in))
			if err != nil {
				t.Fatalf("normaliseMetadata(%q) error: %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("normaliseMetadata(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormaliseMetadata_RecoversInsertBytes(t *testing.T) {
	// When Record inserts metadata, it does json.Marshal of map[string]any.
	// When Verify reads it back, normaliseMetadata should reproduce the
	// exact same bytes regardless of how the DB formatted the column.
	original := map[string]any{"nested": map[string]any{"b": 2, "a": 1}, "x": 5.0}
	insertBytes, _ := json.Marshal(original)

	// Simulate Postgres adding spaces and Go re-Unmarshalling them on read.
	pgBytes := []byte(`{"nested": {"a": 1, "b": 2}, "x": 5}`)
	verifyBytes, err := normaliseMetadata(pgBytes)
	if err != nil {
		t.Fatalf("normaliseMetadata: %v", err)
	}
	if string(insertBytes) != string(verifyBytes) {
		t.Errorf("round-trip mismatch:\n insert: %s\n verify: %s", insertBytes, verifyBytes)
	}
}
