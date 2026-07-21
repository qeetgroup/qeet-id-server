package anthropic_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/anthropic"
)

// cannedSSE is a representative Anthropic SSE stream for a simple text reply.
// It exercises the text_delta path and the end_turn stop_reason.
const cannedSSE = `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type":"ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":", world!"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}

`

// cannedToolUseSSE exercises the tool_use path: a tool block + input_json_delta.
const cannedToolUseSSE = `event: message_start
data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-sonnet-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":20,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_abc123","name":"search_users","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"q\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"alice\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":15}}

event: message_stop
data: {"type":"message_stop"}

`

func makeTestServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

func TestStream_TextReply(t *testing.T) {
	srv := makeTestServer(cannedSSE)
	defer srv.Close()

	c := anthropic.New("test-key", srv.URL, "claude-sonnet-5", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), anthropic.MessagesRequest{
		Messages: []anthropic.Message{
			{Role: "user", Content: []anthropic.ContentBlock{{Type: "text", Text: "hi"}}},
		},
	})

	var textParts []string
	var gotStop string
	for ev := range events {
		switch ev.Type {
		case anthropic.EventContentBlockDelta:
			if ev.TextDelta != "" {
				textParts = append(textParts, ev.TextDelta)
			}
		case anthropic.EventMessageDelta:
			gotStop = ev.StopReason
		}
	}
	if err := <-errC; err != nil {
		t.Fatalf("stream error: %v", err)
	}

	got := strings.Join(textParts, "")
	if got != "Hello, world!" {
		t.Errorf("text = %q, want %q", got, "Hello, world!")
	}
	if gotStop != "end_turn" {
		t.Errorf("stop_reason = %q, want %q", gotStop, "end_turn")
	}
}

func TestStream_ToolUse(t *testing.T) {
	srv := makeTestServer(cannedToolUseSSE)
	defer srv.Close()

	c := anthropic.New("test-key", srv.URL, "claude-sonnet-5", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), anthropic.MessagesRequest{
		Messages: []anthropic.Message{
			{Role: "user", Content: []anthropic.ContentBlock{{Type: "text", Text: "search for alice"}}},
		},
	})

	var toolID, toolName, inputJSON string
	var gotStop string
	for ev := range events {
		switch ev.Type {
		case anthropic.EventContentBlockStart:
			if ev.ToolUseID != "" {
				toolID = ev.ToolUseID
				toolName = ev.ToolUseName
			}
		case anthropic.EventContentBlockDelta:
			inputJSON += ev.InputJSONDelta
		case anthropic.EventMessageDelta:
			gotStop = ev.StopReason
		}
	}
	if err := <-errC; err != nil {
		t.Fatalf("stream error: %v", err)
	}

	if toolID != "toolu_abc123" {
		t.Errorf("tool id = %q, want toolu_abc123", toolID)
	}
	if toolName != "search_users" {
		t.Errorf("tool name = %q, want search_users", toolName)
	}
	wantInput := `{"q":"alice"}`
	if inputJSON != wantInput {
		t.Errorf("input json = %q, want %q", inputJSON, wantInput)
	}
	if gotStop != "tool_use" {
		t.Errorf("stop_reason = %q, want tool_use", gotStop)
	}
}

func TestStream_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"invalid api key"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := anthropic.New("bad-key", srv.URL, "claude-sonnet-5", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), anthropic.MessagesRequest{
		Messages: []anthropic.Message{
			{Role: "user", Content: []anthropic.ContentBlock{{Type: "text", Text: "hi"}}},
		},
	})
	for range events {
	}
	err := <-errC
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q should mention status 401", err.Error())
	}
}
