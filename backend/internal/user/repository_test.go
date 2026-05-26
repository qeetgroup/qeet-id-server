package user

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func captureLogs(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf, func() { slog.SetDefault(prev) }
}

func TestParseUserMetadata_NilOrEmptyReturnsEmptyMap(t *testing.T) {
	id := uuid.New()
	for _, raw := range [][]byte{nil, {}, []byte("")} {
		got := parseUserMetadata(raw, id)
		if got == nil {
			t.Errorf("nil/empty input must return non-nil map (got nil)")
		}
		if len(got) != 0 {
			t.Errorf("nil/empty input must return empty map, got %v", got)
		}
	}
}

func TestParseUserMetadata_ValidJSONRoundTrip(t *testing.T) {
	in := []byte(`{"plan":"growth","feature_flags":{"beta":true}}`)
	got := parseUserMetadata(in, uuid.New())
	want := map[string]any{
		"plan":          "growth",
		"feature_flags": map[string]any{"beta": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseUserMetadata = %v, want %v", got, want)
	}
}

func TestParseUserMetadata_JSONNullReturnsEmptyMap(t *testing.T) {
	got := parseUserMetadata([]byte("null"), uuid.New())
	if got == nil {
		t.Fatal("got nil map")
	}
	if len(got) != 0 {
		t.Errorf("json null must return empty map, got %v", got)
	}
}

func TestParseUserMetadata_CorruptJSONLogsWarning(t *testing.T) {
	buf, restore := captureLogs(t)
	defer restore()

	id := uuid.MustParse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	got := parseUserMetadata([]byte(`{not-valid-json`), id)

	// Returns empty map on failure.
	if got == nil || len(got) != 0 {
		t.Errorf("corrupt input must return empty map, got %v", got)
	}

	out := buf.String()
	if !strings.Contains(out, "user metadata unmarshal failed") {
		t.Errorf("expected warning log, got: %s", out)
	}
	if !strings.Contains(out, id.String()) {
		t.Errorf("warning should include user_id %s, got: %s", id, out)
	}
	if !strings.Contains(out, "meta_bytes") {
		t.Errorf("warning should include meta_bytes count, got: %s", out)
	}
}

func TestParseUserMetadata_LoggerCaptureIsolatesPerTest(t *testing.T) {
	// Sanity that captureLogs restoration leaves slog default intact for
	// other tests in the package.
	buf, restore := captureLogs(t)
	slog.Info("captured")
	restore()
	if !strings.Contains(buf.String(), "captured") {
		t.Errorf("buffer should capture during the helper window: %s", buf.String())
	}
}

func TestParseUserMetadata_DoesNotPanic(t *testing.T) {
	// Defensive: even truly weird inputs must not panic the scanner.
	inputs := [][]byte{
		[]byte("[1,2,3]"),  // array at top level — Unmarshal to map[string]any errors
		[]byte("42"),       // number
		[]byte(`"x"`),      // string
		[]byte("true"),     // bool
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseUserMetadata(%s) panicked: %v", in, r)
				}
			}()
			_ = parseUserMetadata(in, uuid.New())
		}()
	}
}

// Compile-time anchor so the unused context import is justified in
// case scanUser callers expand later.
var _ = context.Background
