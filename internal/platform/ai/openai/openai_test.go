package openai_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/openai"
)

// cannedOpenAITextSSE is a representative OpenAI Chat Completions SSE stream
// for a simple text reply. Exercises the text-delta path and the "stop"
// finish_reason (mapped to "end_turn" in the neutral format).
const cannedOpenAITextSSE = `data: {"id":"chatcmpl-001","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

data: {"id":"chatcmpl-001","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-001","choices":[{"index":0,"delta":{"content":", world!"},"finish_reason":null}]}

data: {"id":"chatcmpl-001","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

`

// cannedOpenAIToolSSE exercises the tool-use path: a tool call with streaming
// argument JSON, terminated by finish_reason="tool_calls" (mapped to "tool_use").
const cannedOpenAIToolSSE = `data: {"id":"chatcmpl-002","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc123","type":"function","function":{"name":"search_users","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-002","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-002","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"alice\"}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-002","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`

func makeOpenAITestServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

func TestOpenAIStream_TextReply(t *testing.T) {
	srv := makeOpenAITestServer(cannedOpenAITextSSE)
	defer srv.Close()

	c := openai.New("test-key", srv.URL, "gpt-4o", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), "system prompt",
		[]ai.Message{{Role: "user", Content: []ai.ContentBlock{{Type: "text", Text: "hi"}}}},
		nil,
	)

	var textParts []string
	var gotStop string
	for ev := range events {
		switch ev.Type {
		case ai.EventTextDelta:
			textParts = append(textParts, ev.TextDelta)
		case ai.EventStop:
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

func TestOpenAIStream_ToolUse(t *testing.T) {
	srv := makeOpenAITestServer(cannedOpenAIToolSSE)
	defer srv.Close()

	c := openai.New("test-key", srv.URL, "gpt-4o", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), "system prompt",
		[]ai.Message{{Role: "user", Content: []ai.ContentBlock{{Type: "text", Text: "search for alice"}}}},
		nil,
	)

	var toolID, toolName, inputJSON string
	var gotStop string
	for ev := range events {
		switch ev.Type {
		case ai.EventToolCallStart:
			if ev.ToolIndex == 0 {
				toolID = ev.ToolID
				toolName = ev.ToolName
			}
		case ai.EventToolCallDelta:
			inputJSON += ev.ToolInputDelta
		case ai.EventStop:
			gotStop = ev.StopReason
		}
	}
	if err := <-errC; err != nil {
		t.Fatalf("stream error: %v", err)
	}

	if toolID != "call_abc123" {
		t.Errorf("tool id = %q, want call_abc123", toolID)
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

func TestOpenAIStream_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"invalid api key","type":"invalid_request_error"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := openai.New("bad-key", srv.URL, "gpt-4o", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), "", nil, nil)
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

// TestOpenAIStream_RequestFormat verifies that the client sends the system
// prompt as a system message, converts neutral messages correctly (user text,
// assistant tool calls, tool results), and formats tools correctly.
func TestOpenAIStream_RequestFormat(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = b
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srv.Close()

	toolInput := json.RawMessage(`{"q":"alice"}`)
	toolResultContent := json.RawMessage(`"found 2 users"`)

	messages := []ai.Message{
		{Role: "user", Content: []ai.ContentBlock{{Type: "text", Text: "search for alice"}}},
		{Role: "assistant", Content: []ai.ContentBlock{
			{Type: "tool_use", ID: "call_xyz", Name: "search_users", Input: toolInput},
		}},
		{Role: "tool", Content: []ai.ContentBlock{
			{Type: "tool_result", ToolUseID: "call_xyz", Content: toolResultContent},
		}},
	}
	tools := []ai.ToolDef{
		{Name: "search_users", Description: "Search users", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	c := openai.New("test-key", srv.URL, "gpt-4o", 512, srv.Client())
	events, errC := c.Stream(context.Background(), "be helpful", messages, tools)
	for range events {
	}
	if err := <-errC; err != nil {
		t.Fatalf("stream error: %v", err)
	}

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role      string `json:"role"`
			Content   any    `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls,omitempty"`
			ToolCallID string `json:"tool_call_id,omitempty"`
		} `json:"messages"`
		Tools []struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(capturedBody, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	// 4 messages: system + user + assistant + tool
	if len(req.Messages) != 4 {
		t.Errorf("want 4 messages, got %d: %+v", len(req.Messages), req.Messages)
	}
	if req.Messages[0].Role != "system" {
		t.Errorf("messages[0].role = %q, want system", req.Messages[0].Role)
	}
	if req.Messages[1].Role != "user" {
		t.Errorf("messages[1].role = %q, want user", req.Messages[1].Role)
	}
	if req.Messages[2].Role != "assistant" {
		t.Errorf("messages[2].role = %q, want assistant", req.Messages[2].Role)
	}
	if len(req.Messages[2].ToolCalls) != 1 {
		t.Errorf("assistant message: want 1 tool_call, got %d", len(req.Messages[2].ToolCalls))
	} else {
		tc := req.Messages[2].ToolCalls[0]
		if tc.ID != "call_xyz" {
			t.Errorf("tool_call id = %q, want call_xyz", tc.ID)
		}
		if tc.Function.Name != "search_users" {
			t.Errorf("tool_call name = %q, want search_users", tc.Function.Name)
		}
	}
	if req.Messages[3].Role != "tool" {
		t.Errorf("messages[3].role = %q, want tool", req.Messages[3].Role)
	}
	if req.Messages[3].ToolCallID != "call_xyz" {
		t.Errorf("tool message tool_call_id = %q, want call_xyz", req.Messages[3].ToolCallID)
	}
	// Tool result content should be the unwrapped string.
	if content, ok := req.Messages[3].Content.(string); !ok || content != "found 2 users" {
		t.Errorf("tool message content = %v, want \"found 2 users\"", req.Messages[3].Content)
	}
	// Tools array.
	if len(req.Tools) != 1 || req.Tools[0].Function.Name != "search_users" {
		t.Errorf("tools = %+v, want search_users", req.Tools)
	}
}

// TestOpenAIStreamReportsTheTokensUsed checks that the turn asks for its
// token counts and reports the last chunk's.
func TestOpenAIStreamReportsTheTokensUsed(t *testing.T) {
	var asked bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		asked = strings.Contains(string(body), `"stream_options":{"include_usage":true}`)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(cannedOpenAITextSSE[:strings.Index(cannedOpenAITextSSE, "data: [DONE]")] +
			"data: {\"id\":\"chatcmpl-001\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n"))
	}))
	defer srv.Close()
	c := openai.New("test-key", srv.URL, "gpt-4o", 1024, srv.Client())
	events, errC := c.Stream(context.Background(), "", []ai.Message{{Role: "user", Content: []ai.ContentBlock{{Type: "text", Text: "hi"}}}}, nil)
	var in, out int
	for ev := range events {
		if ev.Type == ai.EventUsage {
			in, out = ev.InputTokens, ev.OutputTokens
		}
	}
	if err := <-errC; err != nil {
		t.Fatal(err)
	}
	if !asked || in != 11 || out != 4 {
		t.Errorf("asked for usage %v; got %d in, %d out; want 11 and 4", asked, in, out)
	}
}

const toolsDone = `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n"

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
