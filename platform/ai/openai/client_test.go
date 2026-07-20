package openai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/platform/ai"
	"github.com/qeetgroup/qeet-id-server/platform/ai/openai"
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
			Role       string `json:"role"`
			Content    any    `json:"content"`
			ToolCalls  []struct {
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
