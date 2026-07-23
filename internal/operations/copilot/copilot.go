// Package copilot is the AI copilot inference service for the admin console.
// It persists conversation and message history (tenant + user scoped), drives
// the Anthropic tool-orchestration loop, and exposes the results over SSE.
//
// Security invariant: the copilot NEVER executes a domain mutation. Tool calls
// are emitted as SSE events; the browser executes them under the user's own
// token so RBAC and audit are inherited, never bypassed.
package copilot

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/copilot/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Conversation is a named thread between one user and the copilot.
type Conversation struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	UserID    uuid.UUID `json:"user_id"`
	Title     string    `json:"title"`
	Pinned    bool      `json:"pinned"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Message is one turn in a conversation. Content is stored as a JSON array of
// Anthropic content blocks so tool turns round-trip losslessly. Redacted:
// no secret artifacts are persisted.
type Message struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	ConversationID uuid.UUID       `json:"conversation_id"`
	Role           string          `json:"role"`
	Content        json.RawMessage `json:"content"`
	CreatedAt      time.Time       `json:"created_at"`
}

// CreateConversationInput holds the optional fields for a new conversation.
type CreateConversationInput struct {
	Title string `json:"title"`
}

// PatchConversationInput carries mutable fields on an existing conversation.
type PatchConversationInput struct {
	Title  *string `json:"title"`
	Pinned *bool   `json:"pinned"`
}

// ToolResultInput is one tool execution result posted back by the browser
// after client-side tool execution. Sensitive artifacts (secrets, keys) must
// be stripped by the client before posting; only the redacted summary reaches
// the model and the database.
type ToolResultInput struct {
	ToolCallID string         `json:"tool_call_id"`
	Name       string         `json:"name"`
	Output     map[string]any `json:"output,omitempty"`
	Error      *ToolCallError `json:"error,omitempty"`
}

// ToolCallError is the error payload a client posts when a tool execution
// failed on the browser side.
type ToolCallError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// serviceStore is the persistence interface consumed by Handler. *Service
// satisfies it. Declared by the consumer (Handler) per Go's "accept interfaces,
// return concretes" convention — this allows tests to inject stubs without a
// live database connection.
type serviceStore interface {
	Pool() *pgxpool.Pool
	CreateConversation(ctx context.Context, tenantID, userID uuid.UUID, in CreateConversationInput) (*Conversation, error)
	ListConversations(ctx context.Context, tenantID, userID uuid.UUID) ([]Conversation, error)
	GetConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID) (*Conversation, []Message, error)
	PatchConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID, in PatchConversationInput) (*Conversation, error)
	DeleteConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID) error
	AppendMessage(ctx context.Context, tenantID, conversationID uuid.UUID, role string, content json.RawMessage) (*Message, error)
}

// Service owns conversation and message persistence via sqlc-generated queries.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns a Service backed by the given pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Pool returns the underlying connection pool. Used by Handler for audit
// recording, which needs to begin its own transaction outside the service layer.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// CreateConversation inserts a new conversation for the given tenant+user.
func (s *Service) CreateConversation(ctx context.Context, tenantID, userID uuid.UUID, in CreateConversationInput) (*Conversation, error) {
	title := in.Title
	if title == "" {
		title = "New conversation"
	}
	row, err := s.q.CreateConversation(ctx, dbgen.CreateConversationParams{
		TenantID: tenantID,
		UserID:   userID,
		Title:    title,
	})
	if err != nil {
		return nil, err
	}
	return convFromRow(row), nil
}

// ListConversations returns all conversations for a tenant+user, ordered by
// pinned-first then most-recently-updated.
func (s *Service) ListConversations(ctx context.Context, tenantID, userID uuid.UUID) ([]Conversation, error) {
	rows, err := s.q.ListConversations(ctx, dbgen.ListConversationsParams{
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Conversation, 0, len(rows))
	for _, r := range rows {
		out = append(out, *convFromRow(r))
	}
	return out, nil
}

// GetConversation returns a conversation with its messages. Returns
// errs.ErrNotFound when the conversation does not exist or belongs to a
// different tenant/user.
func (s *Service) GetConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID) (*Conversation, []Message, error) {
	row, err := s.q.GetConversation(ctx, dbgen.GetConversationParams{
		ID:       conversationID,
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errs.ErrNotFound
		}
		return nil, nil, err
	}
	msgs, err := s.listMessages(ctx, tenantID, conversationID)
	if err != nil {
		return nil, nil, err
	}
	return convFromRow(row), msgs, nil
}

// PatchConversation updates title and/or pinned on a conversation. Returns
// errs.ErrNotFound when the conversation does not exist or is out of scope.
func (s *Service) PatchConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID, in PatchConversationInput) (*Conversation, error) {
	row, err := s.q.PatchConversation(ctx, dbgen.PatchConversationParams{
		Title:    in.Title,
		Pinned:   in.Pinned,
		ID:       conversationID,
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return convFromRow(row), nil
}

// DeleteConversation removes a conversation and all its messages (cascade).
// Returns errs.ErrNotFound when the conversation is out of scope.
func (s *Service) DeleteConversation(ctx context.Context, tenantID, userID, conversationID uuid.UUID) error {
	n, err := s.q.DeleteConversation(ctx, dbgen.DeleteConversationParams{
		ID:       conversationID,
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// AppendMessage inserts a message row and bumps the conversation updated_at
// in a single transaction. content must be a valid JSON array of Anthropic
// content blocks.
func (s *Service) AppendMessage(ctx context.Context, tenantID, conversationID uuid.UUID, role string, content json.RawMessage) (*Message, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)

	msgRow, err := qtx.InsertMessage(ctx, dbgen.InsertMessageParams{
		TenantID:       tenantID,
		ConversationID: conversationID,
		Role:           role,
		Content:        content,
	})
	if err != nil {
		return nil, err
	}

	if err := qtx.TouchConversation(ctx, dbgen.TouchConversationParams{
		ConversationID: conversationID,
		TenantID:       tenantID,
	}); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return msgFromRow(msgRow), nil
}

// listMessages returns all messages for a conversation in chronological order.
func (s *Service) listMessages(ctx context.Context, tenantID, conversationID uuid.UUID) ([]Message, error) {
	rows, err := s.q.ListMessages(ctx, dbgen.ListMessagesParams{
		ConversationID: conversationID,
		TenantID:       tenantID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(rows))
	for _, r := range rows {
		out = append(out, *msgFromRow(r))
	}
	return out, nil
}

// convFromRow maps a dbgen.CopilotConversation to the domain Conversation type.
func convFromRow(r dbgen.CopilotConversation) *Conversation {
	return &Conversation{
		ID:        r.ID,
		TenantID:  r.TenantID,
		UserID:    r.UserID,
		Title:     r.Title,
		Pinned:    r.Pinned,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// msgFromRow maps a dbgen.CopilotMessage to the domain Message type.
func msgFromRow(r dbgen.CopilotMessage) *Message {
	return &Message{
		ID:             r.ID,
		TenantID:       r.TenantID,
		ConversationID: r.ConversationID,
		Role:           r.Role,
		Content:        r.Content,
		CreatedAt:      r.CreatedAt,
	}
}
