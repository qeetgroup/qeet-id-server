// Package anthropic is a thin streaming client for the Anthropic Messages API
// (transport only: base URL, auth header, SSE parsing). It imports nothing from
// domains/* — the copilot domain imports this, not the reverse (arch rule R1).
package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// DefaultBaseURL is the Anthropic API base URL.
	DefaultBaseURL = "https://api.anthropic.com"

	// DefaultModel is the default model used when none is specified.
	DefaultModel = "claude-sonnet-5"

	// apiVersion is the Anthropic API version header value.
	apiVersion = "2023-06-01"
)

// Client is a streaming Anthropic Messages API client. Inject a custom
// HTTPClient and BaseURL to intercept calls in tests (feed canned SSE bytes).
type Client struct {
	APIKey     string
	BaseURL    string
	Model      string
	MaxTokens  int
	HTTPClient *http.Client
}

// New returns a Client with the given API key and defaults.
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

// ToolDef is the Anthropic tool definition shape sent in the request.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ContentBlock represents a single content element in a message.
// Anthropic supports text, tool_use, and tool_result block types.
type ContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`          // tool_use: tool call id
	Name      string          `json:"name,omitempty"`        // tool_use / tool_result
	Input     json.RawMessage `json:"input,omitempty"`       // tool_use input
	ToolUseID string          `json:"tool_use_id,omitempty"` // tool_result
	Content   json.RawMessage `json:"content,omitempty"`     // tool_result content
}

// Message is one turn in the conversation history.
type Message struct {
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
}

// MessagesRequest is the body sent to POST /v1/messages.
type MessagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
	Tools     []ToolDef `json:"tools,omitempty"`
	Stream    bool      `json:"stream"`
}

// EventType represents the type of an SSE event from the Anthropic API.
type EventType string

const (
	EventMessageStart      EventType = "message_start"
	EventContentBlockStart EventType = "content_block_start"
	EventContentBlockDelta EventType = "content_block_delta"
	EventContentBlockStop  EventType = "content_block_stop"
	EventMessageDelta      EventType = "message_delta"
	EventMessageStop       EventType = "message_stop"
	EventError             EventType = "error"
	EventPing              EventType = "ping"
)

// StreamEvent is a parsed SSE event from the Anthropic streaming response.
type StreamEvent struct {
	Type    EventType       `json:"type"`
	RawData json.RawMessage `json:"-"`
}

// deltaPayload is embedded in content_block_delta events.
type deltaPayload struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`         // text_delta
	JSON string `json:"partial_json,omitempty"` // input_json_delta
}

// contentBlockDeltaEvent is the data payload for content_block_delta events.
type contentBlockDeltaEvent struct {
	Index int          `json:"index"`
	Delta deltaPayload `json:"delta"`
}

// contentBlockStartEvent is the data payload for content_block_start events.
type contentBlockStartEvent struct {
	Index        int          `json:"index"`
	ContentBlock ContentBlock `json:"content_block"`
}

// messageDeltaEvent carries stop_reason from message_delta events.
type messageDeltaEvent struct {
	Delta struct {
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Usage struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ParsedEvent is a fully decoded streaming event with convenience fields.
type ParsedEvent struct {
	Type EventType

	// Set when Type == EventContentBlockStart and it's a tool_use block.
	ToolUseID   string
	ToolUseName string

	// Set when Type == EventContentBlockDelta.
	TextDelta      string // text_delta
	InputJSONDelta string // input_json_delta

	// Set when Type == EventMessageDelta.
	StopReason string

	// Set when Type == EventError.
	ErrorMessage string
}

// Stream sends a Messages request to the Anthropic API and returns a channel
// of ParsedEvents. The channel is closed when the stream ends (message_stop)
// or on error; the final error (if any) is returned via the errC channel.
//
// The caller owns closing ctx to abort the request. Errors during reading are
// emitted as EventError events and then the events channel is closed.
func (c *Client) Stream(ctx context.Context, req MessagesRequest) (<-chan ParsedEvent, <-chan error) {
	req.Model = c.Model
	req.MaxTokens = c.MaxTokens
	req.Stream = true

	events := make(chan ParsedEvent, 64)
	errC := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errC)

		body, err := json.Marshal(req)
		if err != nil {
			errC <- fmt.Errorf("anthropic: marshal request: %w", err)
			return
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			errC <- fmt.Errorf("anthropic: build request: %w", err)
			return
		}
		httpReq.Header.Set("x-api-key", c.APIKey)
		httpReq.Header.Set("anthropic-version", apiVersion)
		httpReq.Header.Set("content-type", "application/json")
		httpReq.Header.Set("accept", "text/event-stream")

		resp, err := c.HTTPClient.Do(httpReq)
		if err != nil {
			errC <- fmt.Errorf("anthropic: http: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			errC <- fmt.Errorf("anthropic: status %d: %s", resp.StatusCode, string(b))
			return
		}

		if err := parseSS(ctx, resp.Body, events); err != nil {
			errC <- err
		}
	}()

	return events, errC
}

// parseSS parses the SSE stream from the Anthropic API and sends ParsedEvents
// to the out channel. It returns when the stream ends (message_stop event) or
// when the context is cancelled.
func parseSS(ctx context.Context, r io.Reader, out chan<- ParsedEvent) error {
	scanner := bufio.NewScanner(r)
	var (
		eventName string
		dataLines []string
	)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			dataLines = dataLines[:0]

		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))

		case line == "":
			// Blank line — dispatch the accumulated event.
			if eventName == "" {
				continue
			}
			rawData := strings.Join(dataLines, "")
			ev, err := parseEvent(EventType(eventName), rawData)
			if err == nil {
				out <- ev
			}
			// Stop after the stream terminator.
			if EventType(eventName) == EventMessageStop {
				return nil
			}
			eventName = ""
			dataLines = dataLines[:0]
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("anthropic: scan: %w", err)
	}
	return nil
}

// parseEvent decodes one SSE event from its name and raw JSON data string.
func parseEvent(t EventType, data string) (ParsedEvent, error) {
	ev := ParsedEvent{Type: t}
	switch t {
	case EventContentBlockStart:
		var p contentBlockStartEvent
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return ev, err
		}
		if p.ContentBlock.Type == "tool_use" {
			ev.ToolUseID = p.ContentBlock.ID
			ev.ToolUseName = p.ContentBlock.Name
		}

	case EventContentBlockDelta:
		var p contentBlockDeltaEvent
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return ev, err
		}
		switch p.Delta.Type {
		case "text_delta":
			ev.TextDelta = p.Delta.Text
		case "input_json_delta":
			ev.InputJSONDelta = p.Delta.JSON
		}

	case EventMessageDelta:
		var p messageDeltaEvent
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return ev, err
		}
		ev.StopReason = p.Delta.StopReason

	case EventError:
		var p struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			ev.ErrorMessage = data
		} else {
			ev.ErrorMessage = p.Error.Message
		}
	}
	return ev, nil
}
