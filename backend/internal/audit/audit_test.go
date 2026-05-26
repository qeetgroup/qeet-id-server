package audit

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fixed values so the test is deterministic.
var (
	fixedID        = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fixedTenantID  = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fixedActorID   = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	fixedResource  = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	fixedCreatedAt = time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
)

func sampleEvent() Event {
	tid := fixedTenantID
	actor := fixedActorID
	resource := fixedResource
	return Event{
		TenantID:     &tid,
		ActorUserID:  &actor,
		ActorType:    "user",
		Action:       "user.create",
		ResourceType: "user",
		ResourceID:   &resource,
		IP:           "192.168.1.1",
		UserAgent:    "test-agent",
		RequestID:    "req-1",
		Metadata:     map[string]any{"k": "v", "n": 42.0},
	}
}

func TestCanonicalize_Deterministic(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	a, err := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, _ := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	if string(a) != string(b) {
		t.Errorf("canonicalize must be deterministic: %s vs %s", a, b)
	}
}

func TestCanonicalize_Snapshot(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	got, err := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// If this snapshot changes, every existing audit chain in production
	// breaks. Bump a chain-version column before changing the canonical
	// format.
	want := `{"id":"11111111-1111-4111-8111-111111111111","tenant_id":"22222222-2222-4222-8222-222222222222","actor_user_id":"33333333-3333-4333-8333-333333333333","actor_type":"user","action":"user.create","resource_type":"user","resource_id":"44444444-4444-4444-8444-444444444444","ip":"192.168.1.1","user_agent":"test-agent","request_id":"req-1","metadata":{"k":"v","n":42},"created_at":"2026-05-26T10:00:00Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}`
	if string(got) != want {
		t.Errorf("canonical bytes changed.\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalize_NilUUIDsRenderEmpty(t *testing.T) {
	e := Event{
		ActorType:    "system",
		Action:       "system.boot",
		ResourceType: "platform",
		Metadata:     nil,
	}
	meta := []byte("{}")
	out, err := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	s := string(out)
	for _, fld := range []string{`"tenant_id":""`, `"actor_user_id":""`, `"resource_id":""`} {
		if !strings.Contains(s, fld) {
			t.Errorf("expected %s in canonical: %s", fld, s)
		}
	}
}

func TestCanonicalize_MetadataKeyOrderIndependent(t *testing.T) {
	e1 := sampleEvent()
	e2 := sampleEvent()
	// Same map, different construction — Go map iteration is random
	// but json.Marshal of maps sorts keys, so canonical bytes must match.
	e2.Metadata = map[string]any{"n": 42.0, "k": "v"}
	m1, _ := json.Marshal(e1.Metadata)
	m2, _ := json.Marshal(e2.Metadata)
	a, _ := canonicalize(e1, fixedID, fixedCreatedAt, m1, chainSeed)
	b, _ := canonicalize(e2, fixedID, fixedCreatedAt, m2, chainSeed)
	if string(a) != string(b) {
		t.Errorf("canonical bytes must be map-order-independent:\n a=%s\n b=%s", a, b)
	}
}

func TestHashHex_KnownValue(t *testing.T) {
	got := hashHex([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("hashHex(hello) = %s, want %s", got, want)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("hashHex output must be valid hex: %v", err)
	}
}

func TestChainSeed_IsAllZeros(t *testing.T) {
	if len(chainSeed) != 64 {
		t.Errorf("chainSeed must be 64 hex chars, got %d", len(chainSeed))
	}
	for i, c := range chainSeed {
		if c != '0' {
			t.Errorf("chainSeed[%d] = %q, want '0'", i, c)
		}
	}
}

func TestNormaliseMetadata_RoundTripCanonical(t *testing.T) {
	// Simulate what Postgres returns for JSONB: same logical structure,
	// possibly with whitespace.
	cases := []struct {
		in   string
		want string
	}{
		{`{"a":1,"b":2}`, `{"a":1,"b":2}`},
		{`{"a": 1, "b": 2}`, `{"a":1,"b":2}`},        // spaces stripped
		{`{"b":2,"a":1}`, `{"a":1,"b":2}`},           // keys sorted
		{``, `{}`},                                    // empty becomes {}
		{`null`, `{}`},                                // null becomes {}
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

func TestChainHashes_LinkProperly(t *testing.T) {
	// First row in a chain uses the seed; the second uses the first's hash.
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)

	canon1, _ := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	hash1 := hashHex(canon1)

	id2 := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	t2 := fixedCreatedAt.Add(time.Second)
	canon2, _ := canonicalize(e, id2, t2, meta, hash1)
	hash2 := hashHex(canon2)

	if hash1 == hash2 {
		t.Error("two consecutive rows must have different hashes")
	}
	// Tampering with the first row's data should change hash1, breaking
	// the link to hash2.
	tampered := e
	tampered.Action = "user.delete"
	tamperedMeta, _ := json.Marshal(tampered.Metadata)
	canon1b, _ := canonicalize(tampered, fixedID, fixedCreatedAt, tamperedMeta, chainSeed)
	if hashHex(canon1b) == hash1 {
		t.Error("tampering with action must change row hash")
	}
}

func TestCanonicalize_PrevHashAffectsOutput(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	a, _ := canonicalize(e, fixedID, fixedCreatedAt, meta, chainSeed)
	b, _ := canonicalize(e, fixedID, fixedCreatedAt, meta, strings.Repeat("f", 64))
	if string(a) == string(b) {
		t.Error("prev_hash must be embedded in canonical output")
	}
}
