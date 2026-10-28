package qeetai

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// fakeStream is a provider stream that sends events, then, unless it is
// cancelled first, keeps sending text until it is, as a provider that never
// stops would. It reports in stopped when it has ended.
func fakeStream(ctx context.Context, events []ai.Event, endless bool) (<-chan ai.Event, <-chan error, <-chan struct{}) {
	out, errC, stopped := make(chan ai.Event), make(chan error, 1), make(chan struct{})
	go func() {
		defer close(stopped)
		defer close(errC)
		defer close(out)
		send := func(ev ai.Event) bool {
			select {
			case out <- ev:
				return true
			case <-ctx.Done():
				errC <- ctx.Err()
				return false
			}
		}
		for _, ev := range events {
			if !send(ev) {
				return
			}
		}
		for endless {
			if !send(ai.Event{Type: ai.EventTextDelta, TextDelta: "more"}) {
				return
			}
		}
	}()
	return out, errC, stopped
}

// collectOf runs collect over events with a reply limit of maxOutput bytes,
// returning what it gathered and the SSE frames it sent.
func collectOf(t *testing.T, events []ai.Event, endless bool, maxOutput int) (string, []*toolUseAccum, bool, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, errC, stopped := fakeStream(ctx, events, endless)
	rec := httptest.NewRecorder()
	text, tools, ok := collect(stream, errC, cancel, newSSEWriter(rec), maxOutput)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the provider stream was not stopped")
	}
	return text, tools, ok, rec.Body.String()
}

func start(slot int, id string) ai.Event {
	return ai.Event{Type: ai.EventToolCallStart, ToolIndex: slot, ToolID: id, ToolName: "search_users"}
}

func input(slot int, s string) ai.Event {
	return ai.Event{Type: ai.EventToolCallDelta, ToolIndex: slot, ToolInputDelta: s}
}

// TestCollectTakesSeveralToolCalls checks that calls on slots 0, 1, 2 are
// gathered with their inputs, beside the text.
func TestCollectTakesSeveralToolCalls(t *testing.T) {
	text, tools, ok, frames := collectOf(t, []ai.Event{
		{Type: ai.EventTextDelta, TextDelta: "Looking"},
		start(0, "a"), input(0, `{"q":`), start(1, "b"), input(0, `"x"}`), input(1, `{}`),
		start(2, "c"),
		{Type: ai.EventStop, StopReason: "tool_use"},
	}, false, DefaultLimits.OutputBytes)
	if !ok || text != "Looking" || len(tools) != 3 {
		t.Fatalf("collect = %q, %d calls, %v; frames %s", text, len(tools), ok, frames)
	}
	for i, want := range []string{`a {"q":"x"}`, `b {}`, `c `} {
		if got := tools[i].ID + " " + tools[i].Input.String(); got != want {
			t.Errorf("call %d = %q, want %q", i, got, want)
		}
	}
}

// TestCollectRefusesAToolCallOutOfBounds checks that a call on a slot other
// than the next, past ai.MaxToolCalls, input for a call not started, or an
// input past ai.MaxToolInputBytes refuses the turn, stops the provider and
// ends the stream with an error.
func TestCollectRefusesAToolCallOutOfBounds(t *testing.T) {
	var tooMany []ai.Event
	for i := range ai.MaxToolCalls + 1 {
		tooMany = append(tooMany, start(i, "c"))
	}
	big := strings.Repeat("a", ai.MaxToolInputBytes/2+1)
	for name, events := range map[string][]ai.Event{
		"a huge slot":          {start(1<<40, "a")},
		"a skipped slot":       {start(0, "a"), start(2, "b")},
		"a negative slot":      {start(-1, "a")},
		"a slot started twice": {start(0, "a"), start(0, "b")},
		"one call too many":    tooMany,
		"input for no call":    {start(0, "a"), input(1, "{}")},
		"a negative input":     {start(0, "a"), input(-1, "{}")},
		"an input too large":   {start(0, "a"), input(0, big), input(0, big)},
	} {
		t.Run(name, func(t *testing.T) {
			_, tools, ok, frames := collectOf(t, events, true, DefaultLimits.OutputBytes)
			if ok || tools != nil {
				t.Fatalf("collect accepted it: %d calls", len(tools))
			}
			if !strings.Contains(frames, "event: error") || !strings.Contains(frames, `"reason":"error"`) {
				t.Errorf("frames %q, want an error and done{error}", frames)
			}
		})
	}
}

// TestCollectCutsTheReplyAtTheOutputLimit checks that a reply past the limit
// ends there, on a whole character, with the provider stopped and the calls
// it had begun dropped, and is kept as the turn's reply.
func TestCollectCutsTheReplyAtTheOutputLimit(t *testing.T) {
	text, tools, ok, frames := collectOf(t, []ai.Event{
		start(0, "a"),
		{Type: ai.EventTextDelta, TextDelta: "héllo "},
		{Type: ai.EventTextDelta, TextDelta: "wörld"},
	}, true, 9)
	if !ok || tools != nil || text != "héllo w" || !utf8.ValidString(text) {
		t.Fatalf("collect = %q, %d calls, %v; want the reply cut to %q and no calls", text, len(tools), ok, "héllo w")
	}
	if strings.Contains(frames, "event: error") {
		t.Errorf("a reply cut at the limit sent an error: %s", frames)
	}
}

func msg(role string, size int) Message {
	return Message{Role: role, Content: json.RawMessage(strings.Repeat("x", size))}
}

// TestRecentHistory checks that the history sent is the longest tail within
// the byte limit that begins with a person's message, and nothing when the
// latest turn alone is over it.
func TestRecentHistory(t *testing.T) {
	history := []Message{msg("user", 10), msg("assistant", 10), msg("user", 10), msg("assistant", 10), msg("tool", 10), msg("assistant", 10)}
	for _, tc := range []struct {
		max, want int
	}{
		{1000, 6}, // everything
		{59, 4},   // the first turn doesn't fit
		{40, 4},   // the latest turn exactly
		{39, 0},   // the latest turn alone is over the limit
	} {
		if got := recentHistory(history, tc.max); len(got) != tc.want || (len(got) > 0 && got[0].Role != "user") {
			t.Errorf("recentHistory within %d bytes: %d messages starting %q, want %d starting with the user's", tc.max, len(got), roleOf(got), tc.want)
		}
	}
	if got := recentHistory(history[3:], 1000); len(got) != 0 {
		t.Errorf("a history with no message of the user's: %d messages, want none", len(got))
	}
}

func roleOf(msgs []Message) string {
	if len(msgs) == 0 {
		return ""
	}
	return msgs[0].Role
}
