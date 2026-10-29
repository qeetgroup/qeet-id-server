package openai_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/openai"
)

// toolFrame is one SSE line carrying a tool-call delta: id and name when
// given, and arguments.
func toolFrame(index int64, id, name, args string) string {
	call := fmt.Sprintf(`{"index":%d`, index)
	if id != "" {
		call += fmt.Sprintf(`,"id":%q,"type":"function"`, id)
	}
	call += fmt.Sprintf(`,"function":{"name":%q,"arguments":%q}}`, name, args)
	return `data: {"choices":[{"index":0,"delta":{"tool_calls":[` + call + `]},"finish_reason":null}]}` + "\n\n"
}

const toolsDone = `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n"

// streamOf runs the client against an endpoint answering body and returns the
// events it emitted and the stream's error.
func streamOf(t *testing.T, body string) ([]ai.Event, error) {
	t.Helper()
	srv := makeOpenAITestServer(body)
	defer srv.Close()
	events, errC := openai.New("k", srv.URL, "m", 64, srv.Client()).Stream(context.Background(), "", nil, nil)
	var got []ai.Event
	for ev := range events {
		got = append(got, ev)
	}
	return got, <-errC
}

// calls is the tool calls in events, by slot: id, name and input.
func calls(t *testing.T, events []ai.Event) []string {
	t.Helper()
	var out []string
	for _, ev := range events {
		switch ev.Type {
		case ai.EventToolCallStart:
			if ev.ToolIndex != len(out) {
				t.Fatalf("a call started on slot %d, want the next, %d", ev.ToolIndex, len(out))
			}
			out = append(out, ev.ToolID+" "+ev.ToolName+" ")
		case ai.EventToolCallDelta:
			if ev.ToolIndex < 0 || ev.ToolIndex >= len(out) {
				t.Fatalf("input for slot %d, with %d calls started", ev.ToolIndex, len(out))
			}
			out[ev.ToolIndex] += ev.ToolInputDelta
		}
	}
	return out
}

// TestToolIndicesBecomeDenseSlots checks that sparse, huge and repeated
// provider indices go out on slots 0, 1, 2 in the order the calls start, a
// second start of an index is ignored, and input sent before its call started
// is dropped.
func TestToolIndicesBecomeDenseSlots(t *testing.T) {
	body := toolFrame(9, "", "", `{"early":1}`) +
		toolFrame(7, "call_a", "search_users", "") +
		toolFrame(1<<40, "call_b", "list_sessions", `{"q":`) +
		toolFrame(7, "", "", `{"x":1}`) +
		toolFrame(7, "call_again", "other", "") +
		toolFrame(1<<40, "", "", `"y"}`) +
		toolFrame(9, "call_c", "audit_log", `{}`) +
		toolsDone
	events, err := streamOf(t, body)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	got := calls(t, events)
	want := []string{`call_a search_users {"x":1}`, `call_b list_sessions {"q":"y"}`, `call_c audit_log {}`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls %q, want %q", got, want)
	}
}

// TestToolCallsOutOfBoundsEndTheStream checks that a negative index, a call
// beyond ai.MaxToolCalls or an input beyond ai.MaxToolInputBytes ends the
// stream with an error, the offending event not sent.
func TestToolCallsOutOfBoundsEndTheStream(t *testing.T) {
	tooMany := ""
	for i := range ai.MaxToolCalls + 1 {
		tooMany += toolFrame(int64(i*3), fmt.Sprintf("call_%d", i), "search_users", "{}")
	}
	chunk := strings.Repeat("a", 30<<10)
	tooLarge := toolFrame(0, "call_big", "search_users", `{"q":"`)
	for range ai.MaxToolInputBytes/len(chunk) + 1 {
		tooLarge += toolFrame(0, "", "", chunk)
	}
	for name, tc := range map[string]struct {
		body      string
		wantCalls int
	}{
		"a negative start":        {toolFrame(0, "call_ok", "search_users", "{}") + toolFrame(-1, "call_neg", "search_users", "{}"), 1},
		"a negative input":        {toolFrame(0, "call_ok", "search_users", "") + toolFrame(-3, "", "", "{}"), 1},
		"one call too many":       {tooMany, ai.MaxToolCalls},
		"an input over the limit": {tooLarge, 1},
	} {
		t.Run(name, func(t *testing.T) {
			events, err := streamOf(t, tc.body+toolsDone)
			if err == nil {
				t.Fatal("the stream ended without an error")
			}
			if got := calls(t, events); len(got) != tc.wantCalls {
				t.Errorf("%d calls sent, want %d", len(got), tc.wantCalls)
			}
			for _, ev := range events {
				if ev.Type == ai.EventToolCallStart && ev.ToolID == "call_neg" {
					t.Error("the call with a negative index was sent")
				}
				if ev.Type == ai.EventStop {
					t.Error("the stream went on to its stop after a call out of bounds")
				}
			}
		})
	}
}

// TestStreamStopsWhenCancelled checks that cancelling the context ends a
// stream the endpoint keeps open, without the caller reading further.
func TestStreamStopsWhenCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`data: {"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}` + "\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	events, errC := openai.New("k", srv.URL, "m", 64, srv.Client()).Stream(ctx, "", nil, nil)
	if ev := <-events; ev.Type != ai.EventTextDelta {
		t.Fatalf("first event %+v, want the text", ev)
	}
	cancel()
	done := make(chan error)
	go func() {
		for range events {
		}
		done <- <-errC
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled stream ended without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream kept going after its context was cancelled")
	}
}
