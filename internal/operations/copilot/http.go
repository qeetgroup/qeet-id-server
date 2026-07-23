package copilot

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler owns the HTTP surface for the copilot feature.
// Configured is true when a provider API key is present; when false,
// conversation CRUD still works but …/messages returns 409.
type Handler struct {
	Service      serviceStore
	Orchestrator *Orchestrator
	Configured   bool
	Provider     string
	Model        string
}

// Mount registers all 7 copilot routes on the authenticated router group.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/copilot/status", h.status)
	r.Post("/copilot/conversations", h.createConversation)
	r.Get("/copilot/conversations", h.listConversations)
	r.Get("/copilot/conversations/{conversationID}", h.getConversation)
	r.Patch("/copilot/conversations/{conversationID}", h.patchConversation)
	r.Delete("/copilot/conversations/{conversationID}", h.deleteConversation)
	r.Post("/copilot/conversations/{conversationID}/messages", h.streamMessages)
}

// status returns the copilot configuration state. Never returns key material.
//
//	GET /v1/copilot/status → { configured, provider, model }
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"configured": h.Configured,
		"provider":   h.Provider,
		"model":      h.Model,
	})
}

// createConversation creates a new conversation for the authenticated user.
//
//	POST /v1/copilot/conversations
func (h *Handler) createConversation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	var in CreateConversationInput
	// Body is optional (title defaults server-side); ignore decode errors for
	// empty bodies so the client can POST with no body.
	_ = httpx.DecodeJSON(r, &in)

	conv, err := h.Service.CreateConversation(r.Context(), tenantID, userID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conv)
}

// listConversations lists conversations for the authenticated user.
//
//	GET /v1/copilot/conversations → { items: Conversation[] }
func (h *Handler) listConversations(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	items, err := h.Service.ListConversations(r.Context(), tenantID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if items == nil {
		items = []Conversation{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// getConversation returns a conversation with its full message history.
//
//	GET /v1/copilot/conversations/{conversationID}
func (h *Handler) getConversation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conv, msgs, err := h.Service.GetConversation(r.Context(), tenantID, userID, convID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if msgs == nil {
		msgs = []Message{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"conversation": conv,
		"messages":     msgs,
	})
}

// patchConversation renames or pins/unpins a conversation.
//
//	PATCH /v1/copilot/conversations/{conversationID}
func (h *Handler) patchConversation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in PatchConversationInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conv, err := h.Service.PatchConversation(r.Context(), tenantID, userID, convID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conv)
}

// deleteConversation deletes a conversation and all its messages.
//
//	DELETE /v1/copilot/conversations/{conversationID}
func (h *Handler) deleteConversation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteConversation(r.Context(), tenantID, userID, convID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// streamMessages handles a new turn of the conversation, streaming the
// Anthropic response over SSE. The write deadline is extended well beyond the
// server default (HTTP_WRITE_TIMEOUT 30s) so a long streamed turn does not
// time out. X-Accel-Buffering: no is set to prevent Nginx/Caddy buffering.
//
//	POST /v1/copilot/conversations/{conversationID}/messages
func (h *Handler) streamMessages(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// Gate: provider must be configured to stream; CRUD still works without it.
	if !h.Configured {
		httpx.WriteError(w, r, errs.New("copilot_unconfigured", http.StatusConflict,
			"AI copilot is not configured — set COPILOT_PROVIDER and COPILOT_API_KEY"))
		return
	}

	// Security: verify ownership BEFORE any write. GetConversation scopes by
	// tenant AND user — a request from user A with a conversation owned by user B
	// returns ErrNotFound here, preventing stored-prompt injection across users in
	// the same tenant. This check precedes body parsing, SSE headers, and all DB
	// writes so no side effect occurs on an unauthorized request.
	if _, _, err := h.Service.GetConversation(r.Context(), tenantID, userID, convID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	var body struct {
		Message     string            `json:"message"`
		ToolResults []ToolResultInput `json:"tool_results"`
		Context     json.RawMessage   `json:"context"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if body.Message == "" && len(body.ToolResults) == 0 {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("message or tool_results required"))
		return
	}

	// Extend write deadline: the default HTTP_WRITE_TIMEOUT (30s) is too short
	// for a full streaming turn. Reset it to 10 minutes on this connection.
	if rc := http.NewResponseController(w); rc != nil {
		if conn, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && conn != nil {
			_ = conn // addr obtained; deadline set below via ResponseController
		}
		if err := rc.SetWriteDeadline(time.Now().Add(10 * time.Minute)); err != nil {
			// Not fatal — log and continue; worst case the connection times out.
			slog.Warn("copilot: extend write deadline", "err", err)
		}
	}

	// SSE headers — set before the first write.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // prevents Nginx/Caddy buffering

	sse := newSSEWriter(w)
	if sse == nil {
		// ResponseWriter does not support flushing — very unlikely in production.
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Keep-alive pings every 15s so proxies don't drop the connection.
	donePing := make(chan struct{})
	defer close(donePing)
	sse.startKeepAlive(donePing, 15*time.Second)

	p := httpx.PrincipalFromCtx(r.Context())
	actor := audit.Actor{
		UserID:    p.UserID,
		Type:      p.ActorType,
		IP:        httpx.ClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: httpx.RequestID(r),
	}

	// Persist the incoming user turn.
	if body.Message != "" {
		userContent := []map[string]any{{"type": "text", "text": body.Message}}
		contentJSON, err := json.Marshal(userContent)
		if err != nil {
			sse.send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize message"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
		if _, err := h.Service.AppendMessage(r.Context(), tenantID, convID, "user", contentJSON); err != nil {
			slog.Error("copilot: persist user message", "err", err)
			sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to store message"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
		// Audit: user sent a message to the copilot.
		h.recordMessageAudit(r, actor, tenantID, convID)
	}

	// Persist tool_results as a "tool"-role message (continuation turn).
	if len(body.ToolResults) > 0 {
		toolContent := buildToolResultContent(body.ToolResults)
		contentJSON, err := json.Marshal(toolContent)
		if err != nil {
			sse.send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize tool results"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
		if _, err := h.Service.AppendMessage(r.Context(), tenantID, convID, "tool", contentJSON); err != nil {
			slog.Error("copilot: persist tool results", "err", err)
			sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to store tool results"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
	}

	// Run the orchestration loop.
	pageCtx := ""
	if len(body.Context) > 0 && string(body.Context) != "null" {
		pageCtx = string(body.Context)
	}
	h.Orchestrator.Run(r.Context(), turnContext{
		tenantID:       tenantID,
		userID:         userID,
		conversationID: convID,
		pageContext:    pageCtx,
		actor:          actor,
	}, sse)
}

// recordMessageAudit writes a copilot.message.sent audit row.
func (h *Handler) recordMessageAudit(r *http.Request, actor audit.Actor, tenantID, convID uuid.UUID) {
	tx, err := h.Service.Pool().Begin(r.Context())
	if err != nil {
		slog.Warn("copilot: audit message tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	tid := tenantID
	cid := convID
	err = audit.Record(r.Context(), tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actor.UserID,
		ActorType:    actor.Type,
		Action:       "copilot.message.sent",
		ResourceType: "copilot_conversation",
		ResourceID:   &cid,
		IP:           actor.IP,
		UserAgent:    actor.UserAgent,
		RequestID:    actor.RequestID,
		Metadata:     map[string]any{"conversation_id": convID.String()},
	})
	if err != nil {
		slog.Warn("copilot: audit message.sent", "err", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Warn("copilot: audit message.sent commit", "err", err)
	}
}

// requireTenantUser extracts and validates the tenant and user from the JWT
// principal. Handlers must never take tenant/user from URL or body.
func (h *Handler) requireTenantUser(w http.ResponseWriter, r *http.Request) (tenantID, userID uuid.UUID, ok bool) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

// parseConversationID parses the {conversationID} path parameter.
func parseConversationID(r *http.Request) (uuid.UUID, error) {
	raw := chi.URLParam(r, "conversationID")
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid conversationID")
	}
	return id, nil
}
