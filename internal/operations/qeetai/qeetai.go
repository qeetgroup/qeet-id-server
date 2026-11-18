// Package qeetai serves the Qeet AI assistant for the admin console: it stores
// each user's conversations, streams model turns over SSE and manages
// per-organization provider keys. The server never runs a tool; tool calls go to the
// browser, which runs them under the user's own token.
package qeetai

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Conversation is a named thread between one user and the qeetai.
type Conversation struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         uuid.UUID `json:"user_id"`
	Title          string    `json:"title"`
	Pinned         bool      `json:"pinned"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Message is one turn in a conversation. Content is stored as a JSON array of
// Anthropic content blocks so tool turns round-trip losslessly. Redacted:
// no secret artifacts are persisted.
type Message struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
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

// serviceStore is the persistence Handler needs. *Service implements it, and
// tests substitute a stub.
type serviceStore interface {
	CreateConversation(ctx context.Context, organizationID, userID uuid.UUID, in CreateConversationInput) (*Conversation, error)
	ListConversations(ctx context.Context, organizationID, userID uuid.UUID) ([]Conversation, error)
	GetConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID) (*Conversation, []Message, error)
	PatchConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID, in PatchConversationInput) (*Conversation, error)
	DeleteConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID) error
	AppendMessage(ctx context.Context, organizationID, conversationID uuid.UUID, role string, content json.RawMessage) (*Message, error)
	BeginTurn(ctx context.Context, organizationID, conversationID uuid.UUID) (release func(), err error)
	RecordMessageSent(ctx context.Context, organizationID, conversationID uuid.UUID, actor audit.Actor) error
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

// CreateConversation inserts a new conversation for the given organization+user.
func (s *Service) CreateConversation(ctx context.Context, organizationID, userID uuid.UUID, in CreateConversationInput) (*Conversation, error) {
	title := in.Title
	if title == "" {
		title = "New conversation"
	}
	row, err := s.q.CreateConversation(ctx, dbgen.CreateConversationParams{
		OrganizationID: organizationID,
		UserID:         userID,
		Title:          title,
	})
	if err != nil {
		return nil, err
	}
	return convFromRow(row), nil
}

// ListConversations returns all conversations for an organization+user, ordered by
// pinned-first then most-recently-updated.
func (s *Service) ListConversations(ctx context.Context, organizationID, userID uuid.UUID) ([]Conversation, error) {
	rows, err := s.q.ListConversations(ctx, dbgen.ListConversationsParams{
		OrganizationID: organizationID,
		UserID:         userID,
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
// different organization/user.
func (s *Service) GetConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID) (*Conversation, []Message, error) {
	row, err := s.q.GetConversation(ctx, dbgen.GetConversationParams{
		ID:             conversationID,
		OrganizationID: organizationID,
		UserID:         userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errs.ErrNotFound
		}
		return nil, nil, err
	}
	msgs, err := s.listMessages(ctx, organizationID, conversationID)
	if err != nil {
		return nil, nil, err
	}
	return convFromRow(row), msgs, nil
}

// PatchConversation updates title and/or pinned on a conversation. Returns
// errs.ErrNotFound when the conversation does not exist or is out of scope.
func (s *Service) PatchConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID, in PatchConversationInput) (*Conversation, error) {
	row, err := s.q.PatchConversation(ctx, dbgen.PatchConversationParams{
		Title:          in.Title,
		Pinned:         in.Pinned,
		ID:             conversationID,
		OrganizationID: organizationID,
		UserID:         userID,
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
func (s *Service) DeleteConversation(ctx context.Context, organizationID, userID, conversationID uuid.UUID) error {
	n, err := s.q.DeleteConversation(ctx, dbgen.DeleteConversationParams{
		ID:             conversationID,
		OrganizationID: organizationID,
		UserID:         userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// RecordMessageSent records that actor sent a message in the conversation: an
// event of its own, after the message is stored.
func (s *Service) RecordMessageSent(ctx context.Context, organizationID, conversationID uuid.UUID, actor audit.Actor) error {
	return audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "qeetai.message.sent", "qeetai_conversation", conversationID,
		map[string]any{"conversation_id": conversationID.String()}))
}

// AppendMessage inserts a message row and bumps the conversation updated_at
// in a single transaction. content must be a valid JSON array of Anthropic
// content blocks.
func (s *Service) AppendMessage(ctx context.Context, organizationID, conversationID uuid.UUID, role string, content json.RawMessage) (*Message, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)

	msgRow, err := qtx.InsertMessage(ctx, dbgen.InsertMessageParams{
		OrganizationID: organizationID,
		ConversationID: conversationID,
		Role:           role,
		Content:        content,
	})
	if err != nil {
		return nil, err
	}

	if err := qtx.TouchConversation(ctx, dbgen.TouchConversationParams{
		ConversationID: conversationID,
		OrganizationID: organizationID,
	}); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return msgFromRow(msgRow), nil
}

// turnTimeout is the longest a turn may run; a turn's hold on its
// conversation older than this, and a minute more, was left by one that never
// finished.
const turnTimeout = 10 * time.Minute

// BeginTurn starts a turn of the conversation, which answers one at a time: it
// returns ErrTurnInProgress while another runs, on any instance.
// Call release when the turn ends.
func (s *Service) BeginTurn(ctx context.Context, organizationID, conversationID uuid.UUID) (release func(), err error) {
	startedAt, err := s.q.ClaimConversationTurn(ctx, dbgen.ClaimConversationTurnParams{
		ConversationID: conversationID, OrganizationID: organizationID, StaleAfterSeconds: (turnTimeout + time.Minute).Seconds(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTurnInProgress
	}
	if err != nil {
		return nil, err
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.q.ReleaseConversationTurn(ctx, dbgen.ReleaseConversationTurnParams{
			ConversationID: conversationID, OrganizationID: organizationID, StartedAt: startedAt,
		}); err != nil {
			slog.Warn("qeetai: end the turn", "conversation_id", conversationID, "err", err)
		}
	}, nil
}

// TurnHistory returns the conversation's latest maxMessages messages, oldest
// first: the most of its history one turn reads. Returns errs.ErrNotFound
// when the conversation does not exist or belongs to another organization or user.
func (s *Service) TurnHistory(ctx context.Context, organizationID, userID, conversationID uuid.UUID, maxMessages int) ([]Message, error) {
	if _, err := s.q.GetConversation(ctx, dbgen.GetConversationParams{ID: conversationID, OrganizationID: organizationID, UserID: userID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	rows, err := s.q.ListRecentMessages(ctx, dbgen.ListRecentMessagesParams{
		ConversationID: conversationID, OrganizationID: organizationID, MaxMessages: int32(min(maxMessages, math.MaxInt32)), // #nosec G115 -- clamped
	})
	if err != nil {
		return nil, err
	}
	out := make([]Message, len(rows))
	for i, r := range rows {
		out[len(rows)-1-i] = *msgFromRow(r)
	}
	return out, nil
}

// listMessages returns all messages for a conversation in chronological order.
func (s *Service) listMessages(ctx context.Context, organizationID, conversationID uuid.UUID) ([]Message, error) {
	rows, err := s.q.ListMessages(ctx, dbgen.ListMessagesParams{
		ConversationID: conversationID,
		OrganizationID: organizationID,
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

// convFromRow maps a dbgen.QeetaiConversation to the domain Conversation type.
func convFromRow(r dbgen.QeetaiConversation) *Conversation {
	return &Conversation{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		UserID:         r.UserID,
		Title:          r.Title,
		Pinned:         r.Pinned,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

// msgFromRow maps a dbgen.QeetaiMessage to the domain Message type.
func msgFromRow(r dbgen.QeetaiMessage) *Message {
	return &Message{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		ConversationID: r.ConversationID,
		Role:           r.Role,
		Content:        r.Content,
		CreatedAt:      r.CreatedAt,
	}
}
