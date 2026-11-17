package qeetai

import (
	"context"
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
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the Qeet AI routes. An organization with its own provider key (BYOK)
// may use the assistant on any plan; otherwise the platform key applies, gated
// by Plan. With neither, conversation CRUD still works but posting a message
// returns qeetai_unconfigured.
type Handler struct {
	Service      serviceStore     // conversations and messages
	Orchestrator *Orchestrator    // runs one streamed turn
	Resolver     ProviderResolver // the organization's effective provider, for status and gating
	Config       *ProviderConfig  // backs the BYOK admin endpoints; may be nil in tests
	Plan         PlanGate         // plan gate for the platform key; nil means no gate
	Admin        *Service         // usage and settings, for the organization's admins
}

// PlanGate reports whether a boolean feature is included in an organization's plan.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, organizationID uuid.UUID, feature string) (bool, error)
}

// planAllows reports whether the organization's plan includes the qeetai feature.
// A nil gate (unset) allows it; a resolver error is treated as not allowed.
func (h *Handler) planAllows(r *http.Request, organizationID uuid.UUID) bool {
	if h.Plan == nil {
		return true
	}
	ok, err := h.Plan.FeatureAllowed(r.Context(), organizationID, "ai_qeetai")
	return err == nil && ok
}

// Mount registers the Qeet AI routes on the authenticated router group.
// The provider-config routes are additionally gated to org admins by the
// central permission map (secret.read / secret.write); the rest are user-level.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/qeetai/status", h.status)
	r.Post("/qeetai/conversations", h.createConversation)
	r.Get("/qeetai/conversations", h.listConversations)
	r.Get("/qeetai/conversations/{conversationID}", h.getConversation)
	r.Patch("/qeetai/conversations/{conversationID}", h.patchConversation)
	r.Delete("/qeetai/conversations/{conversationID}", h.deleteConversation)
	r.Post("/qeetai/conversations/{conversationID}/messages", h.streamMessages)

	// BYOK provider config (org owner/admin — see permission map).
	r.Get("/qeetai/provider-config", h.getProviderConfig)
	r.Put("/qeetai/provider-config", h.putProviderConfig)
	r.Delete("/qeetai/provider-config", h.deleteProviderConfig)
	r.Post("/qeetai/provider-config/test", h.testProviderConfig)

	// The organization's use and settings (org admins — see permission map).
	r.Get("/tenants/{tenantID}/qeetai/usage", h.usage)
	r.Get("/tenants/{tenantID}/qeetai/settings", h.settings)
	r.Put("/tenants/{tenantID}/qeetai/settings", h.putSettings)
}

// status reports the organization's Qeet AI state, never key material. source is
// "tenant" (BYOK), "platform" or "none"; only the platform key is plan-gated.
//
//	GET /v1/qeetai/status → { configured, available, provider, model, source }
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"configured": false, "available": false, "source": string(SourceNone)}
	tid, err := httpx.RequireOrganization(r)
	if err == nil && h.Resolver != nil {
		if eff, rerr := h.Resolver.Resolve(r.Context(), tid); rerr == nil {
			configured := eff.Source != SourceNone
			available := false
			if configured {
				// BYOK unlocks the assistant on any plan; the platform fallback
				// stays plan-gated.
				available = eff.Source == SourceOrganization || h.planAllows(r, tid)
			}
			resp = map[string]any{
				"configured": configured,
				"available":  available,
				"provider":   eff.Provider,
				"model":      eff.Model,
				"source":     string(eff.Source),
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// qeetaiAllowed reports whether the organization may use the assistant and the
// resolved config source. An organization with its own provider key (SourceOrganization) is
// allowed on any plan; otherwise the plan gate applies.
func (h *Handler) qeetaiAllowed(r *http.Request, organizationID uuid.UUID) (source ConfigSource, allowed bool) {
	source = SourceNone
	if h.Resolver != nil {
		if eff, err := h.Resolver.Resolve(r.Context(), organizationID); err == nil {
			source = eff.Source
		}
	}
	if source == SourceOrganization {
		return source, true // BYOK bypasses the plan gate
	}
	return source, h.planAllows(r, organizationID)
}

// createConversation creates a new conversation for the authenticated user.
//
//	POST /v1/qeetai/conversations
func (h *Handler) createConversation(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	if _, allowed := h.qeetaiAllowed(r, organizationID); !allowed {
		httpx.WriteError(w, r, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ai_qeetai"}))
		return
	}
	var in CreateConversationInput
	// Body is optional (title defaults server-side); ignore decode errors for
	// empty bodies so the client can POST with no body.
	_ = httpx.DecodeJSON(r, &in)

	conv, err := h.Service.CreateConversation(r.Context(), organizationID, userID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conv)
}

// listConversations lists conversations for the authenticated user.
//
//	GET /v1/qeetai/conversations → { items: Conversation[] }
func (h *Handler) listConversations(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	items, err := h.Service.ListConversations(r.Context(), organizationID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if items == nil {
		items = []Conversation{}
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

// getConversation returns a conversation with its full message history.
//
//	GET /v1/qeetai/conversations/{conversationID}
func (h *Handler) getConversation(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conv, msgs, err := h.Service.GetConversation(r.Context(), organizationID, userID, convID)
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
//	PATCH /v1/qeetai/conversations/{conversationID}
func (h *Handler) patchConversation(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
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
	conv, err := h.Service.PatchConversation(r.Context(), organizationID, userID, convID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conv)
}

// deleteConversation deletes a conversation and all its messages.
//
//	DELETE /v1/qeetai/conversations/{conversationID}
func (h *Handler) deleteConversation(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteConversation(r.Context(), organizationID, userID, convID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// streamMessages runs one conversation turn and streams the reply over SSE,
// raising the write deadline to 10 minutes so long turns don't time out.
//
//	POST /v1/qeetai/conversations/{conversationID}/messages
func (h *Handler) streamMessages(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	convID, err := parseConversationID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// Gate: a provider must be configured (organization BYOK key or platform fallback)
	// to stream; conversation CRUD still works without one.
	source, allowed := h.qeetaiAllowed(r, organizationID)
	if source == SourceNone {
		httpx.WriteError(w, r, errs.ErrQeetAIUnconfigured.WithMessage(
			"Qeet AI is not configured — add your organization's AI provider key in Settings → Qeet AI (or set QEETAI_PROVIDER/QEETAI_API_KEY)"))
		return
	}
	// Plan gate applies only to the platform fallback; BYOK is allowed on any plan.
	if !allowed {
		httpx.WriteError(w, r, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ai_qeetai"}))
		return
	}

	// Verify ownership before any write or SSE header. GetConversation is scoped
	// to organization and user, so another user's conversation returns ErrNotFound and
	// can't have a prompt injected into it.
	if _, _, err := h.Service.GetConversation(r.Context(), organizationID, userID, convID); err != nil {
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

	// One turn at a time in a conversation, on any instance: a second is
	// refused before anything is stored.
	release, err := h.Service.BeginTurn(r.Context(), organizationID, convID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), turnTimeout)
	defer cancel()

	// Extend write deadline: the default HTTP_WRITE_TIMEOUT (30s) is too short
	// for a full streaming turn. Reset it to turnTimeout on this connection.
	if rc := http.NewResponseController(w); rc != nil {
		if conn, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && conn != nil {
			_ = conn // addr obtained; deadline set below via ResponseController
		}
		if err := rc.SetWriteDeadline(time.Now().Add(turnTimeout)); err != nil {
			// Not fatal — log and continue; worst case the connection times out.
			slog.Warn("qeetai: extend write deadline", "err", err)
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
	// stopKeepAlive runs first (defers are LIFO), so the ping goroutine has
	// exited before this handler returns and can never write to a released
	// ResponseWriter.
	donePing := make(chan struct{})
	defer sse.stopKeepAlive()
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
		if _, err := h.Service.AppendMessage(r.Context(), organizationID, convID, "user", contentJSON); err != nil {
			slog.Error("qeetai: persist user message", "err", err)
			sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to store message"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
		// Audit: user sent a message to the qeetai.
		h.recordMessageAudit(r, actor, organizationID, convID)
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
		if _, err := h.Service.AppendMessage(r.Context(), organizationID, convID, "tool", contentJSON); err != nil {
			slog.Error("qeetai: persist tool results", "err", err)
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
	h.Orchestrator.Run(ctx, turnContext{
		organizationID: organizationID,
		userID:         userID,
		conversationID: convID,
		pageContext:    pageCtx,
		actor:          actor,
	}, sse)
}

// recordMessageAudit writes a qeetai.message.sent audit row.
func (h *Handler) recordMessageAudit(r *http.Request, actor audit.Actor, organizationID, convID uuid.UUID) {
	tx, err := h.Service.Pool().Begin(r.Context())
	if err != nil {
		slog.Warn("qeetai: audit message tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	tid := organizationID
	cid := convID
	err = audit.Record(r.Context(), tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    actor.UserID,
		ActorType:      actor.Type,
		Action:         "qeetai.message.sent",
		ResourceType:   "qeetai_conversation",
		ResourceID:     &cid,
		IP:             actor.IP,
		UserAgent:      actor.UserAgent,
		RequestID:      actor.RequestID,
		Metadata:       map[string]any{"conversation_id": convID.String()},
	})
	if err != nil {
		slog.Warn("qeetai: audit message.sent", "err", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Warn("qeetai: audit message.sent commit", "err", err)
	}
}

// --- BYOK provider configuration (org owner/admin) ---

// providerConfigResponse is the masked view returned by get/put. It never
// includes key material — only the effective provider/model and a last-4 hint.
func providerConfigResponse(eff EffectiveConfig, platformFallback bool) map[string]any {
	return map[string]any{
		"source":            string(eff.Source),
		"provider":          eff.Provider,
		"model":             eff.Model,
		"base_url":          eff.BaseURL,
		"max_tokens":        eff.MaxTokens,
		"last4":             eff.Last4,
		"platform_fallback": platformFallback,
	}
}

// getProviderConfig returns the organization's effective provider config (masked).
//
//	GET /v1/qeetai/provider-config
func (h *Handler) getProviderConfig(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	eff, err := h.Config.Resolve(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, providerConfigResponse(eff, h.Config.PlatformConfigured()))
}

// putProviderConfig sets (or rotates) the organization's BYOK provider key.
//
//	PUT /v1/qeetai/provider-config { provider, model, api_key, base_url?, max_tokens? }
func (h *Handler) putProviderConfig(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Provider  string `json:"provider"`
		Model     string `json:"model"`
		APIKey    string `json:"api_key"`
		BaseURL   string `json:"base_url"`
		MaxTokens int    `json:"max_tokens"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	eff, err := h.Config.Set(r.Context(), organizationID, SetProviderInput{
		Provider:  body.Provider,
		Model:     body.Model,
		APIKey:    body.APIKey,
		BaseURL:   body.BaseURL,
		MaxTokens: body.MaxTokens,
		UpdatedBy: userID,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.recordProviderConfigAudit(r, organizationID, userID, "qeetai.provider_config.updated",
		map[string]any{"provider": eff.Provider, "model": eff.Model, "last4": eff.Last4})
	httpx.WriteJSON(w, http.StatusOK, providerConfigResponse(eff, h.Config.PlatformConfigured()))
}

// deleteProviderConfig removes the organization's BYOK key, reverting to the platform
// fallback (or unconfigured).
//
//	DELETE /v1/qeetai/provider-config
func (h *Handler) deleteProviderConfig(w http.ResponseWriter, r *http.Request) {
	organizationID, userID, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	if err := h.Config.Clear(r.Context(), organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.recordProviderConfigAudit(r, organizationID, userID, "qeetai.provider_config.removed", nil)
	w.WriteHeader(http.StatusNoContent)
}

// testProviderConfig checks a provider key and endpoint with a minimal live
// request, without saving, and returns { ok: true } or a 4xx error.
//
//	POST /v1/qeetai/provider-config/test { provider, model, api_key, base_url? }
func (h *Handler) testProviderConfig(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.RequireOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body struct {
		Provider  string `json:"provider"`
		Model     string `json:"model"`
		APIKey    string `json:"api_key"`
		BaseURL   string `json:"base_url"`
		MaxTokens int    `json:"max_tokens"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Config.Test(r.Context(), SetProviderInput{
		Provider:  body.Provider,
		Model:     body.Model,
		APIKey:    body.APIKey,
		BaseURL:   body.BaseURL,
		MaxTokens: body.MaxTokens,
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// recordProviderConfigAudit writes an audit row for a BYOK config change. The
// resource is the organization itself; no key material is ever recorded.
func (h *Handler) recordProviderConfigAudit(r *http.Request, organizationID, userID uuid.UUID, action string, meta map[string]any) {
	if h.Config == nil {
		return
	}
	ctx := r.Context()
	tx, err := h.Config.pool.Begin(ctx)
	if err != nil {
		slog.Warn("qeetai: audit provider-config tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tid := organizationID
	uid := userID
	actorType := "user"
	if p := httpx.PrincipalFromCtx(ctx); p != nil && p.ActorType != "" {
		actorType = p.ActorType
	}
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    &uid,
		ActorType:      actorType,
		Action:         action,
		ResourceType:   "qeetai_provider_config",
		ResourceID:     &tid,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       meta,
	}); err != nil {
		slog.Warn("qeetai: audit provider-config", "err", err, "action", action)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("qeetai: audit provider-config commit", "err", err)
	}
}

// requireOrganizationUser extracts and validates the organization and user from the JWT
// principal. Handlers must never take organization/user from URL or body.
func (h *Handler) requireOrganizationUser(w http.ResponseWriter, r *http.Request) (organizationID, userID uuid.UUID, ok bool) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	return organizationID, userID, true
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
