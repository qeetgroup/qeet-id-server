package audit

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Fixed inputs, so the tests are deterministic.
var (
	fixedID             = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fixedOrganizationID = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fixedActorID        = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	fixedResource       = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	fixedCreatedAt      = time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
)

func sampleEvent() Event {
	tid := fixedOrganizationID
	actor := fixedActorID
	resource := fixedResource
	return Event{
		OrganizationID: &tid,
		ActorUserID:    &actor,
		ActorType:      "user",
		Action:         "user.create",
		ResourceType:   "user",
		ResourceID:     &resource,
		IP:             "192.168.1.1",
		UserAgent:      "test-agent",
		RequestID:      "req-1",
		Metadata:       map[string]any{"k": "v", "n": 42.0},
	}
}

func TestCanonicalize_Deterministic(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	a, err := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, _ := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	if string(a) != string(b) {
		t.Errorf("canonicalize must be deterministic: %s vs %s", a, b)
	}
}

func TestCanonicalize_Snapshot(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	got, err := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// If this snapshot changes, every existing audit chain in production
	// breaks. Bump a chain-version column before changing the canonical
	// format.
	want := `{"id":"11111111-1111-4111-8111-111111111111","organization_id":"22222222-2222-4222-8222-222222222222","actor_user_id":"33333333-3333-4333-8333-333333333333","actor_type":"user","action":"user.create","resource_type":"user","resource_id":"44444444-4444-4444-8444-444444444444","ip":"192.168.1.1","user_agent":"test-agent","request_id":"req-1","metadata":{"k":"v","n":42},"created_at":"2026-05-26T10:00:00Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}`
	if string(got) != want {
		t.Errorf("canonical bytes changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalize_ShardIsHashedBeyondTheFirstChain checks that a row of
// platform chain 0 hashes exactly as the single platform chain's rows did, and
// that a row of another platform chain names its chain in what is hashed, so
// moving it to another chain changes its hash.
func TestCanonicalize_ShardIsHashedBeyondTheFirstChain(t *testing.T) {
	e := sampleEvent()
	e.OrganizationID = nil
	meta, _ := json.Marshal(e.Metadata)
	first, _ := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	if strings.Contains(string(first), "chain_shard") {
		t.Errorf("a chain 0 row names its chain: %s", first)
	}
	other, _ := canonicalize(e, 7, fixedID, fixedCreatedAt, meta, chainSeed)
	if want := strings.TrimSuffix(string(first), "}") + `,"chain_shard":7}`; string(other) != want {
		t.Errorf("a chain 7 row:\n got: %s\nwant: %s", other, want)
	}
	moved, _ := canonicalize(e, 8, fixedID, fixedCreatedAt, meta, chainSeed)
	if hashHex(moved) == hashHex(other) {
		t.Error("a row moved to another platform chain hashes the same")
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
	out, err := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	s := string(out)
	for _, fld := range []string{`"organization_id":""`, `"actor_user_id":""`, `"resource_id":""`} {
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
	a, _ := canonicalize(e1, 0, fixedID, fixedCreatedAt, m1, chainSeed)
	b, _ := canonicalize(e2, 0, fixedID, fixedCreatedAt, m2, chainSeed)
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

func TestChainHashes_LinkProperly(t *testing.T) {
	// First row in a chain uses the seed; the second uses the first's hash.
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)

	canon1, _ := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	hash1 := hashHex(canon1)

	id2 := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	t2 := fixedCreatedAt.Add(time.Second)
	canon2, _ := canonicalize(e, 0, id2, t2, meta, hash1)
	hash2 := hashHex(canon2)

	if hash1 == hash2 {
		t.Error("two consecutive rows must have different hashes")
	}
	// Tampering with the first row's data should change hash1, breaking
	// the link to hash2.
	tampered := e
	tampered.Action = "user.delete"
	tamperedMeta, _ := json.Marshal(tampered.Metadata)
	canon1b, _ := canonicalize(tampered, 0, fixedID, fixedCreatedAt, tamperedMeta, chainSeed)
	if hashHex(canon1b) == hash1 {
		t.Error("tampering with action must change row hash")
	}
}

func TestCanonicalize_PrevHashAffectsOutput(t *testing.T) {
	e := sampleEvent()
	meta, _ := json.Marshal(e.Metadata)
	a, _ := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, chainSeed)
	b, _ := canonicalize(e, 0, fixedID, fixedCreatedAt, meta, strings.Repeat("f", 64))
	if string(a) == string(b) {
		t.Error("prev_hash must be embedded in canonical output")
	}
}

// TestChanges checks that only the fields whose value changed are reported,
// each with its old and new value.
func TestChanges(t *testing.T) {
	got := Changes(
		map[string]any{"name": "Acme", "threshold": 0.7, "on": true},
		map[string]any{"name": "Acme Ltd", "threshold": 0.7, "on": false},
	)
	want := map[string]any{
		"name": map[string]any{"from": "Acme", "to": "Acme Ltd"},
		"on":   map[string]any{"from": true, "to": false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Changes = %v, want %v", got, want)
	}
	if got := Changes(map[string]any{"a": 1}, map[string]any{"a": 1}); len(got) != 0 {
		t.Errorf("Changes of an unchanged field = %v, want none", got)
	}
}

// TestActorOf checks who a request's audit events name: the system with no
// principal, a user for a principal naming no type, and otherwise its type.
func TestActorOf(t *testing.T) {
	userID := uuid.New()
	for _, c := range []struct {
		name      string
		principal *httpx.Principal
		wantType  string
		wantUser  *uuid.UUID
	}{
		{"no principal", nil, "system", nil},
		{"a principal naming no type", &httpx.Principal{UserID: &userID}, "user", &userID},
		{"an API key", &httpx.Principal{ActorType: "api_key"}, "api_key", nil},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("User-Agent", "test-agent")
		if c.principal != nil {
			r = r.WithContext(httpx.WithPrincipal(r.Context(), c.principal))
		}
		a := ActorOf(r)
		if a.Type != c.wantType || a.UserID != c.wantUser || a.UserAgent != "test-agent" {
			t.Errorf("%s: %+v, want type %q and user %v", c.name, a, c.wantType, c.wantUser)
		}
	}
}

// TestEventIn checks the event an actor's action makes: with the actor's
// provenance, on its organization's chain or a platform chain, and with no
// resource for uuid.Nil.
func TestEventIn(t *testing.T) {
	userID, organizationID, resourceID := uuid.New(), uuid.New(), uuid.New()
	a := Actor{UserID: &userID, Type: "user", IP: "203.0.113.7", UserAgent: "ua", RequestID: "req"}
	meta := map[string]any{"k": "v"}

	e := a.EventIn(&organizationID, "thing.done", "thing", resourceID, meta)
	if e.OrganizationID == nil || *e.OrganizationID != organizationID || e.ResourceID == nil || *e.ResourceID != resourceID ||
		e.ActorUserID != &userID || e.ActorType != "user" || e.IP != a.IP || e.UserAgent != a.UserAgent || e.RequestID != a.RequestID ||
		e.Action != "thing.done" || e.ResourceType != "thing" || e.Metadata["k"] != "v" {
		t.Errorf("organization event: %+v", e)
	}
	if e.OrganizationID == &organizationID {
		t.Error("the event shares the caller's organization variable")
	}
	if p := a.EventIn(nil, "thing.done", "thing", resourceID, nil); p.OrganizationID != nil {
		t.Errorf("platform event on organization %v", *p.OrganizationID)
	}
	if n := a.EventIn(&organizationID, "thing.done", "thing", uuid.Nil, nil); n.ResourceID != nil {
		t.Errorf("uuid.Nil recorded as resource %v", *n.ResourceID)
	}
	if ev, in := a.Event(organizationID, "x", "y", resourceID, meta), a.EventIn(&organizationID, "x", "y", resourceID, meta); *ev.OrganizationID != *in.OrganizationID || *ev.ResourceID != *in.ResourceID {
		t.Errorf("Event %+v differs from EventIn %+v", ev, in)
	}
}
