package main

import (
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

// TestReplayFilterReadsItsFlags checks that replay-dead-letters picks the
// event type and time it is given, everything without them, and refuses
// anything else.
func TestReplayFilterReadsItsFlags(t *testing.T) {
	since := time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC)
	for _, c := range []struct {
		args []string
		want outbox.ReplayFilter
	}{
		{nil, outbox.ReplayFilter{}},
		{[]string{"-type", "user.created"}, outbox.ReplayFilter{EventType: "user.created"}},
		{[]string{"-since", "2026-10-27T09:30:00Z", "-type", "user.created"}, outbox.ReplayFilter{EventType: "user.created", Since: since}},
	} {
		got, err := replayFilter(c.args)
		if err != nil || got.EventType != c.want.EventType || !got.Since.Equal(c.want.Since) {
			t.Errorf("%v: %+v, %v; want %+v", c.args, got, err, c.want)
		}
	}
	for _, args := range [][]string{{"-since", "yesterday"}, {"-kind", "x"}, {"user.created"}} {
		if _, err := replayFilter(args); err == nil {
			t.Errorf("%v: accepted, want an error", args)
		}
	}
}
