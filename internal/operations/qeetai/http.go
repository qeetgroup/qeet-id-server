package qeetai

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/sse"
)

// Handler serves the Qeet AI routes. An organization with its own provider key (BYOK)
// may use the assistant on any plan; otherwise the platform key applies, gated
// by Plan. With neither, conversation CRUD still works but posting a message
// returns qeetai_unconfigured.
type Handler struct {
	Service      serviceStore          // conversations and messages
	Orchestrator *Orchestrator         // runs one streamed turn
	Resolver     ProviderResolver      // the organization's effective provider, for status and gating
	Config       *ProviderConfig       // backs the BYOK admin endpoints; may be nil in tests
	Plan         entitlements.PlanGate // plan gate for the platform key; nil means no gate
	Admin        *Service              // usage and settings, for the organization's admins
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
	r.Get("/organizations/{organizationID}/qeetai/usage", h.usage)
	r.Get("/organizations/{organizationID}/qeetai/settings", h.settings)
	r.Put("/organizations/{organizationID}/qeetai/settings", h.putSettings)
}

// status reports the organization's Qeet AI state, never key material. source is
// "organization" (BYOK), "platform" or "none"; only the platform key is plan-gated.
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
		httpx.WriteError(w, r, ErrUnconfigured.WithMessage(
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

	// The stream may stay open for the whole turn, past HTTP_WRITE_TIMEOUT.
	out := sse.Open(w, turnTimeout)
	if out == nil {
		httpx.WriteError(w, r, errs.ErrInternalServer.WithDetail("streaming not supported"))
		return
	}
	// Keep-alive pings every 15s so proxies don't drop the connection.
	defer out.KeepAlive(15 * time.Second)()

	actor := audit.ActorOf(r)

	if !h.storeTurn(r, out, organizationID, convID, body.Message, body.ToolResults, actor) {
		return
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
	}, out)
}

// storeTurn stores the turn's user message, recorded as actor's, and its
// tool_results as a "tool"-role message (a continuation turn). A turn it
// can't store ends the stream with an error and returns false.
func (h *Handler) storeTurn(r *http.Request, out *sse.Writer, organizationID, convID uuid.UUID, message string, toolResults []ToolResultInput, actor audit.Actor) bool {
	if message != "" {
		userContent := []map[string]any{{"type": "text", "text": message}}
		contentJSON, err := json.Marshal(userContent)
		if err != nil {
			out.Send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize message"})
			out.Send(EventTypeDone, doneData{Reason: "error"})
			return false
		}
		if _, err := h.Service.AppendMessage(r.Context(), organizationID, convID, "user", contentJSON); err != nil {
			slog.Error("qeetai: persist user message", "err", err)
			out.Send(EventTypeError, errorData{Code: "db_error", Message: "failed to store message"})
			out.Send(EventTypeDone, doneData{Reason: "error"})
			return false
		}
		if err := h.Service.RecordMessageSent(r.Context(), organizationID, convID, actor); err != nil {
			slog.Warn("qeetai: audit message.sent", "err", err)
		}
	}
	if len(toolResults) > 0 {
		toolContent := buildToolResultContent(toolResults)
		contentJSON, err := json.Marshal(toolContent)
		if err != nil {
			out.Send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize tool results"})
			out.Send(EventTypeDone, doneData{Reason: "error"})
			return false
		}
		if _, err := h.Service.AppendMessage(r.Context(), organizationID, convID, "tool", contentJSON); err != nil {
			slog.Error("qeetai: persist tool results", "err", err)
			out.Send(EventTypeError, errorData{Code: "db_error", Message: "failed to store tool results"})
			out.Send(EventTypeDone, doneData{Reason: "error"})
			return false
		}
	}
	return true
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
	h.recordProviderConfigAudit(r, organizationID, "qeetai.provider_config.updated",
		map[string]any{"provider": eff.Provider, "model": eff.Model, "last4": eff.Last4})
	httpx.WriteJSON(w, http.StatusOK, providerConfigResponse(eff, h.Config.PlatformConfigured()))
}

// deleteProviderConfig removes the organization's BYOK key, reverting to the platform
// fallback (or unconfigured).
//
//	DELETE /v1/qeetai/provider-config
func (h *Handler) deleteProviderConfig(w http.ResponseWriter, r *http.Request) {
	organizationID, _, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	if err := h.Config.Clear(r.Context(), organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.recordProviderConfigAudit(r, organizationID, "qeetai.provider_config.removed", nil)
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

// recordProviderConfigAudit records a BYOK config change as an event of its
// own, after the change. The resource is the organization itself; no key
// material is ever recorded.
func (h *Handler) recordProviderConfigAudit(r *http.Request, organizationID uuid.UUID, action string, meta map[string]any) {
	if h.Config == nil {
		return
	}
	if err := h.Config.RecordChange(r.Context(), organizationID, action, meta, audit.ActorOf(r)); err != nil {
		slog.Warn("qeetai: audit provider-config", "err", err, "action", action)
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
	return httpx.PathUUID(r, "conversationID", errs.ErrBadRequest.WithDetail("invalid conversationID"))
}

// usage handles GET /v1/organizations/{organizationID}/qeetai/usage.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.UsageOf(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// settings handles GET /v1/organizations/{organizationID}/qeetai/settings.
func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.SettingsOf(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// putSettings handles PUT /v1/organizations/{organizationID}/qeetai/settings.
func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		ConversationRetentionDays *int `json:"conversation_retention_days"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.SetSettings(r.Context(), organizationID, in.ConversationRetentionDays, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
