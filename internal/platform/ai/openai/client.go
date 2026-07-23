// Package openai is a streaming OpenAI Chat Completions client implementing
// ai.Provider. Transport-only (base URL, auth header, SSE parsing); imports
// nothing from domains/*. Also works with any hosted OpenAI-compatible endpoint
// (Groq, OpenRouter, Gemini's OpenAI path) via COPILOT_BASE_URL.
package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

const (
	// DefaultBaseURL is the OpenAI API v1 base URL, used when BaseURL is empty.
	DefaultBaseURL = "https://api.openai.com/v1"

	// DefaultModel is the model used when none is specified.
	DefaultModel = "gpt-4o"
)

// Client is a streaming OpenAI Chat Completions client implementing ai.Provider.
// Inject a custom HTTPClient and BaseURL to intercept calls in tests (feed
// canned SSE bytes), exactly mirroring the anthropic.Client pattern.
type Client struct {
	APIKey     string
	BaseURL    string
	Model      string
	MaxTokens  int
	HTTPClient *http.Client
}

// New returns a Client with the given parameters and sensible defaults.
// An empty baseURL uses DefaultBaseURL (https://api.openai.com/v1) — override
// to point at any hosted OpenAI-compatible endpoint.
func New(apiKey, baseURL, model string, maxTokens int, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if model == "" {
		model = DefaultModel
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		APIKey:     apiKey,
		BaseURL:    baseURL,
		Model:      model,
		MaxTokens:  maxTokens,
		HTTPClient: httpClient,
	}
}

// Stream implements ai.Provider. It converts the neutral conversation history
// and tool definitions to OpenAI Chat Completions format, calls the streaming
// endpoint, and emits normalized ai.Event values.
//
// "tool" role messages (tool_result turns) are converted to OpenAI role="tool"
// messages directly (no remapping required).
func (c *Client) Stream(ctx context.Context, system string, messages []ai.Message, tools []ai.ToolDef) (<-chan ai.Event, <-chan error) {
	out := make(chan ai.Event, 64)
	errC := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errC)

		reqBody := openAIRequest{
			Model:     c.Model,
			MaxTokens: c.MaxTokens,
			Stream:    true,
			Messages:  buildOpenAIMessages(system, messages),
			Tools:     buildOpenAITools(tools),
		}

		body, err := json.Marshal(reqBody)
		if err != nil {
			errC <- fmt.Errorf("openai: marshal request: %w", err)
			return
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.BaseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			errC <- fmt.Errorf("openai: build request: %w", err)
			return
		}
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "text/event-stream")

		resp, err := c.HTTPClient.Do(httpReq)
		if err != nil {
			errC <- fmt.Errorf("openai: http: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			errC <- fmt.Errorf("openai: status %d: %s", resp.StatusCode, string(b))
			return
		}

		if err := parseOpenAISSE(ctx, resp.Body, out); err != nil {
			errC <- err
		}
	}()

	return out, errC
}

// openAIRequest is the body sent to POST /chat/completions.
type openAIRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Stream    bool            `json:"stream"`
	Messages  []openAIMessage `json:"messages"`
	Tools     []openAITool    `json:"tools,omitempty"`
}

// openAIMessage is one entry in the messages array. Content is *string so that
// nil marshals to JSON null (required for assistant turns that only have
// tool_calls and no text content).
type openAIMessage struct {
	Role       string          `json:"role"`
	Content    *string         `json:"content"`
	ToolCalls  []openAICallDef `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"` // role=tool only
}

type openAICallDef struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // always "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON string (not object)
	} `json:"function"`
}

type openAITool struct {
	Type     string `json:"type"` // always "function"
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"` // same schema as InputSchema
	} `json:"function"`
}

// openAIChunk is a parsed streaming delta from the Chat Completions SSE.
type openAIChunk struct {
	Choices []openAIChoice `json:"choices"`
}

type openAIChoice struct {
	Delta        openAIDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type openAIDelta struct {
	Content   *string           `json:"content"`
	ToolCalls []openAICallDelta `json:"tool_calls,omitempty"`
}

type openAICallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id,omitempty"`   // only in the first delta for this index
	Type     string `json:"type,omitempty"` // only in the first delta
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}

// ptr returns a pointer to s.
func ptr(s string) *string { return &s }

// buildOpenAIMessages builds the OpenAI messages array from the system prompt
// and neutral history. OpenAI uses role:"tool" natively (no remapping needed).
func buildOpenAIMessages(system string, msgs []ai.Message) []openAIMessage {
	out := make([]openAIMessage, 0, len(msgs)+1)
	if system != "" {
		out = append(out, openAIMessage{Role: "system", Content: ptr(system)})
	}
	for _, m := range msgs {
		out = append(out, toOpenAIMessage(m)...)
	}
	return out
}

// toOpenAIMessage converts one neutral ai.Message to 0–N openAIMessage values.
// A "tool" role message can expand to multiple OpenAI messages (one per
// tool_result block) when the assistant invoked several tools at once.
func toOpenAIMessage(m ai.Message) []openAIMessage {
	switch m.Role {
	case "user":
		var sb strings.Builder
		for _, cb := range m.Content {
			if cb.Type == "text" {
				sb.WriteString(cb.Text)
			}
		}
		return []openAIMessage{{Role: "user", Content: ptr(sb.String())}}

	case "assistant":
		var sb strings.Builder
		var calls []openAICallDef
		for _, cb := range m.Content {
			switch cb.Type {
			case "text":
				sb.WriteString(cb.Text)
			case "tool_use":
				args := "{}"
				if len(cb.Input) > 0 {
					args = string(cb.Input)
				}
				call := openAICallDef{ID: cb.ID, Type: "function"}
				call.Function.Name = cb.Name
				call.Function.Arguments = args
				calls = append(calls, call)
			}
		}
		msg := openAIMessage{Role: "assistant"}
		if sb.Len() > 0 {
			msg.Content = ptr(sb.String())
		}
		// content=null when only tool_calls (nil *string marshals to JSON null).
		msg.ToolCalls = calls
		return []openAIMessage{msg}

	case "tool":
		// One OpenAI tool message per tool_result block so each has its own
		// tool_call_id. OpenAI does not batch multiple results in one message.
		var out []openAIMessage
		for _, cb := range m.Content {
			if cb.Type != "tool_result" {
				continue
			}
			// cb.Content is a JSON-encoded string (e.g. `"ok"` or `"{...}"`).
			// Unmarshal to recover the raw string value.
			contentStr := ""
			if len(cb.Content) > 0 {
				var s string
				if err := json.Unmarshal(cb.Content, &s); err == nil {
					contentStr = s
				} else {
					contentStr = string(cb.Content)
				}
			}
			out = append(out, openAIMessage{
				Role:       "tool",
				Content:    ptr(contentStr),
				ToolCallID: cb.ToolUseID,
			})
		}
		return out
	}
	return nil
}

// buildOpenAITools converts neutral tool definitions to the OpenAI tools format.
// InputSchema (JSON Schema) maps directly to the OpenAI "parameters" field.
func buildOpenAITools(tools []ai.ToolDef) []openAITool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]openAITool, 0, len(tools))
	for _, t := range tools {
		var ot openAITool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.InputSchema
		out = append(out, ot)
	}
	return out
}

// parseOpenAISSE reads the OpenAI Chat Completions SSE stream, emitting
// normalized ai.Event values to out until "data: [DONE]" or ctx cancellation.
// OpenAI SSE: one "data: <json>" line per event (no "event:" prefix).
func parseOpenAISSE(ctx context.Context, r io.Reader, out chan<- ai.Event) error {
	scanner := bufio.NewScanner(r)
	// Track which tool indices have been started so we only emit
	// EventToolCallStart once per index.
	startedTools := make(map[int]bool)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			return nil
		}
		if data == "" {
			continue
		}

		var chunk openAIChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			// Malformed chunk — skip; don't abort the stream.
			continue
		}

		for _, choice := range chunk.Choices {
			if choice.Delta.Content != nil && *choice.Delta.Content != "" {
				out <- ai.Event{Type: ai.EventTextDelta, TextDelta: *choice.Delta.Content}
			}

			for _, tc := range choice.Delta.ToolCalls {
				if !startedTools[tc.Index] && tc.ID != "" {
					startedTools[tc.Index] = true
					out <- ai.Event{
						Type:      ai.EventToolCallStart,
						ToolIndex: tc.Index,
						ToolID:    tc.ID,
						ToolName:  tc.Function.Name,
					}
				}
				if tc.Function.Arguments != "" {
					out <- ai.Event{
						Type:           ai.EventToolCallDelta,
						ToolIndex:      tc.Index,
						ToolInputDelta: tc.Function.Arguments,
					}
				}
			}

			// Finish reason — translate OpenAI names to neutral names.
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				reason := *choice.FinishReason
				switch reason {
				case "tool_calls":
					reason = "tool_use"
				case "stop", "length", "content_filter":
					reason = "end_turn"
				}
				out <- ai.Event{Type: ai.EventStop, StopReason: reason}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("openai: scan: %w", err)
	}
	return nil
}
