package qeetai

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// collectOf runs collect over events, returning what it gathered and the SSE
// frames it sent.
func collectOf(t *testing.T, events []ai.Event, endless bool) (string, []*toolUseAccum, bool, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, errC, stopped := fakeStream(ctx, events, endless)
	rec := httptest.NewRecorder()
	text, tools, ok := collect(stream, errC, cancel, newSSEWriter(rec))
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
	}, false)
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
			_, tools, ok, frames := collectOf(t, events, true)
			if ok || tools != nil {
				t.Fatalf("collect accepted it: %d calls", len(tools))
			}
			if !strings.Contains(frames, "event: error") || !strings.Contains(frames, `"reason":"error"`) {
				t.Errorf("frames %q, want an error and done{error}", frames)
			}
		})
	}
}
