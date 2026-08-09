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
)

// Handler owns the HTTP surface for the Qeet AI assistant.
//
// Whether the assistant is usable is resolved per-tenant (Resolver): a tenant
// that has brought its own provider key (BYOK) is configured on any plan; a
// tenant without one falls back to the deployment-level platform key, gated by
// plan. When neither is present, conversation CRUD still works but …/messages
// returns qeetai_unconfigured.
type Handler struct {
	Service      serviceStore
	Orchestrator *Orchestrator
	// Resolver resolves the tenant's effective provider for status + gating
	// (BYOK key → platform fallback → none). An interface so unit tests can stub
	// it without a database.
	Resolver ProviderResolver
	// Config backs the BYOK admin endpoints (get/set/test/remove). May be nil in
	// unit tests that don't exercise those endpoints.
	Config *ProviderConfig
	// Plan gates the assistant by plan (nil = no plan gate) for tenants on the
	// platform fallback. BYOK bypasses this gate entirely.
	Plan PlanGate
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by operations/entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// planAllows reports whether the tenant's plan includes the qeetai feature.
// A nil gate (unset) allows it; a resolver error is treated as not allowed.
func (h *Handler) planAllows(r *http.Request, tenantID uuid.UUID) bool {
	if h.Plan == nil {
		return true
	}
	ok, err := h.Plan.FeatureAllowed(r.Context(), tenantID, "ai_qeetai")
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
}

// status returns the per-tenant Qeet AI configuration state. Never returns key
// material — only the effective provider/model and a source discriminator.
//
//	GET /v1/qeetai/status → { configured, available, provider, model, source }
//
// source is "tenant" (BYOK), "platform" (deployment fallback), or "none".
// available folds in the plan gate for the platform fallback, but BYOK
// (source=tenant) is available on any plan.
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"configured": false, "available": false, "source": string(SourceNone)}
	tid, err := httpx.RequireTenant(r)
	if err == nil && h.Resolver != nil {
		if eff, rerr := h.Resolver.Resolve(r.Context(), tid); rerr == nil {
			configured := eff.Source != SourceNone
			available := false
			if configured {
				// BYOK unlocks the assistant on any plan; the platform fallback
				// stays plan-gated.
				available = eff.Source == SourceTenant || h.planAllows(r, tid)
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

// qeetaiAllowed reports whether the tenant may use the assistant and the
// resolved config source. A tenant with its own provider key (SourceTenant) is
// allowed on any plan; otherwise the plan gate applies.
func (h *Handler) qeetaiAllowed(r *http.Request, tenantID uuid.UUID) (source ConfigSource, allowed bool) {
	source = SourceNone
	if h.Resolver != nil {
		if eff, err := h.Resolver.Resolve(r.Context(), tenantID); err == nil {
			source = eff.Source
		}
	}
	if source == SourceTenant {
		return source, true // BYOK bypasses the plan gate
	}
	return source, h.planAllows(r, tenantID)
}

// createConversation creates a new conversation for the authenticated user.
//
//	POST /v1/qeetai/conversations
func (h *Handler) createConversation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	if _, allowed := h.qeetaiAllowed(r, tenantID); !allowed {
		httpx.WriteError(w, r, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ai_qeetai"}))
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
//	GET /v1/qeetai/conversations → { items: Conversation[] }
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
//	GET /v1/qeetai/conversations/{conversationID}
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
//	PATCH /v1/qeetai/conversations/{conversationID}
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
//	DELETE /v1/qeetai/conversations/{conversationID}
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
//	POST /v1/qeetai/conversations/{conversationID}/messages
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

	// Gate: a provider must be configured (tenant BYOK key or platform fallback)
	// to stream; conversation CRUD still works without one.
	source, allowed := h.qeetaiAllowed(r, tenantID)
	if source == SourceNone {
		httpx.WriteError(w, r, errs.New("qeetai_unconfigured",
			"Qeet AI is not configured — add your organization's AI provider key in Settings → Qeet AI (or set QEETAI_PROVIDER/QEETAI_API_KEY)"))
		return
	}
	// Plan gate applies only to the platform fallback; BYOK is allowed on any plan.
	if !allowed {
		httpx.WriteError(w, r, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ai_qeetai"}))
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
			slog.Error("qeetai: persist user message", "err", err)
			sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to store message"})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			return
		}
		// Audit: user sent a message to the qeetai.
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
	h.Orchestrator.Run(r.Context(), turnContext{
		tenantID:       tenantID,
		userID:         userID,
		conversationID: convID,
		pageContext:    pageCtx,
		actor:          actor,
	}, sse)
}

// recordMessageAudit writes a qeetai.message.sent audit row.
func (h *Handler) recordMessageAudit(r *http.Request, actor audit.Actor, tenantID, convID uuid.UUID) {
	tx, err := h.Service.Pool().Begin(r.Context())
	if err != nil {
		slog.Warn("qeetai: audit message tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	tid := tenantID
	cid := convID
	err = audit.Record(r.Context(), tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actor.UserID,
		ActorType:    actor.Type,
		Action:       "qeetai.message.sent",
		ResourceType: "qeetai_conversation",
		ResourceID:   &cid,
		IP:           actor.IP,
		UserAgent:    actor.UserAgent,
		RequestID:    actor.RequestID,
		Metadata:     map[string]any{"conversation_id": convID.String()},
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

// getProviderConfig returns the tenant's effective provider config (masked).
//
//	GET /v1/qeetai/provider-config
func (h *Handler) getProviderConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	eff, err := h.Config.Resolve(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, providerConfigResponse(eff, h.Config.PlatformConfigured()))
}

// putProviderConfig sets (or rotates) the tenant's BYOK provider key.
//
//	PUT /v1/qeetai/provider-config { provider, model, api_key, base_url?, max_tokens? }
func (h *Handler) putProviderConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
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
	eff, err := h.Config.Set(r.Context(), tenantID, SetProviderInput{
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
	h.recordProviderConfigAudit(r, tenantID, userID, "qeetai.provider_config.updated",
		map[string]any{"provider": eff.Provider, "model": eff.Model, "last4": eff.Last4})
	httpx.WriteJSON(w, http.StatusOK, providerConfigResponse(eff, h.Config.PlatformConfigured()))
}

// deleteProviderConfig removes the tenant's BYOK key, reverting to the platform
// fallback (or unconfigured).
//
//	DELETE /v1/qeetai/provider-config
func (h *Handler) deleteProviderConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	if err := h.Config.Clear(r.Context(), tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.recordProviderConfigAudit(r, tenantID, userID, "qeetai.provider_config.removed", nil)
	w.WriteHeader(http.StatusNoContent)
}

// testProviderConfig validates a provider key + endpoint with a minimal live
// request, WITHOUT saving. Returns { ok: true } on success; a 4xx error
// envelope (qeetai_provider_key_invalid, …) on failure.
//
//	POST /v1/qeetai/provider-config/test { provider, model, api_key, base_url? }
func (h *Handler) testProviderConfig(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.RequireTenant(r); err != nil {
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
// resource is the tenant itself; no key material is ever recorded.
func (h *Handler) recordProviderConfigAudit(r *http.Request, tenantID, userID uuid.UUID, action string, meta map[string]any) {
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

	tid := tenantID
	uid := userID
	actorType := "user"
	if p := httpx.PrincipalFromCtx(ctx); p != nil && p.ActorType != "" {
		actorType = p.ActorType
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "qeetai_provider_config",
		ResourceID:   &tid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	}); err != nil {
		slog.Warn("qeetai: audit provider-config", "err", err, "action", action)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("qeetai: audit provider-config commit", "err", err)
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
