package activity

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestCursorRoundTrip checks that a cursor decodes to the time and id it was
// made from, at any precision and from any time zone.
func TestCursorRoundTrip(t *testing.T) {
	id := uuid.New()
	for _, at := range []time.Time{
		time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 26, 12, 30, 45, 123456000, time.UTC),
		time.Date(2026, 5, 26, 18, 0, 45, 123456789, time.FixedZone("IST", 5*3600+1800)),
	} {
		gotAt, gotID, err := decodeCursor(encodeCursor(at, id))
		if err != nil {
			t.Fatalf("decode the cursor of %s: %v", at, err)
		}
		if !gotAt.Equal(at) || gotID != id {
			t.Errorf("cursor of (%s, %s) decoded to (%s, %s)", at, id, gotAt, gotID)
		}
	}
}

// TestSendActivityWritesCursorAsID checks that an activity frame starts with an
// id line holding the event's cursor, which a reconnecting client sends back as
// Last-Event-ID.
func TestSendActivityWritesCursorAsID(t *testing.T) {
	rec := httptest.NewRecorder()
	ev := newTestEvent("user.created", SeveritySuccess)
	newSSEWriter(rec).sendActivity(ev, ev.At)

	frame := rec.Body.String()
	first, _, _ := strings.Cut(frame, "\n")
	cursor, ok := strings.CutPrefix(first, "id: ")
	if !ok {
		t.Fatalf("frame does not start with an id line:\n%s", frame)
	}
	at, id, err := decodeCursor(cursor)
	if err != nil || !at.Equal(ev.At) || id != ev.ID {
		t.Errorf("frame id decodes to (%s, %s, %v), want (%s, %s)", at, id, err, ev.At, ev.ID)
	}
	if !strings.Contains(frame, "\nevent: activity\ndata: ") || !strings.HasSuffix(frame, "\n\n") {
		t.Errorf("malformed frame:\n%s", frame)
	}
}

// TestStreamEndsWhenTheHubShutsDown checks that an open stream, and one opened
// after, ends with a reconnect hint once the hub shuts down, so a stopping
// server's streams don't hold up its drain.
func TestStreamEndsWhenTheHubShutsDown(t *testing.T) {
	hub := NewHub(nil)
	h := NewHandler(nil, hub)
	tenantID, userID := uuid.New(), uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &httpx.Principal{TenantID: &tenantID, UserID: &userID}
		h.stream(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	read := func() (string, error) {
		resp, err := client.Get(srv.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	const want = "retry: 3000\n\n"

	got := make(chan string, 1)
	go func() {
		body, err := read()
		if err != nil {
			body = err.Error()
		}
		got <- body
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		subscribed := len(hub.subs[tenantID]) > 0
		hub.mu.RUnlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stream never subscribed")
		}
	}
	hub.Shutdown()
	if body := <-got; body != want {
		t.Errorf("open stream at shutdown sent %q, want %q", body, want)
	}

	if body, err := read(); err != nil || body != want {
		t.Errorf("stream opened after shutdown sent %q (%v), want %q", body, err, want)
	}
	hub.Shutdown() // a second call is harmless
}
