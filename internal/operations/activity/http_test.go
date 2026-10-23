package activity

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
