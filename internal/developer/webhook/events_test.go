package webhook

import (
	"errors"
	"slices"
	"testing"
)

// TestSubscribableEvents checks that a subscription names at least one event,
// only ones in the catalogue, each once, and never the test event.
func TestSubscribableEvents(t *testing.T) {
	got, err := subscribableEvents([]string{"user.created", "session.revoked", "user.created"})
	if err != nil || !slices.Equal(got, []string{"user.created", "session.revoked"}) {
		t.Errorf("subscribableEvents = %v, %v; want the two events once each", got, err)
	}
	if _, err := subscribableEvents(nil); !errors.Is(err, ErrEventsRequired) {
		t.Errorf("no events: %v; want %v", err, ErrEventsRequired)
	}
	for _, name := range []string{"user.exploded", TestEvent, ""} {
		if _, err := subscribableEvents([]string{name}); !errors.Is(err, ErrEventUnknown) {
			t.Errorf("%q: %v; want %v", name, err, ErrEventUnknown)
		}
	}
}
