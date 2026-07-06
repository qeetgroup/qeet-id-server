// Package agent provides first-class AI-agent identities: non-human principals
// that authenticate with a secret and receive SHORT-LIVED, scoped access tokens
// marked actor_type="agent" (plus an agent_id claim). Tokens are ephemeral by
// design — an agent re-mints rather than refreshing — and are signed by the
// same platform issuer, so they verify through the standard JWKS/RequireAuth
// path while remaining distinguishable from human and service principals
// (foundational for MCP-server authorization).
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
	"github.com/qeetgroup/qeet-id/platform/security/encryption"
	"github.com/qeetgroup/qeet-id/platform/security/tokens"
)

// EventEmitter enqueues a webhook event for a tenant. Injected (webhook service)
// so this package needn't import webhooks. nil = no-op.
type EventEmitter func(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error

type Service struct {
	pool    *pgxpool.Pool
	issuer  *tokens.Issuer
	emitter EventEmitter
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, issuer: issuer}
}

// SetEmitter wires the webhook event emitter (called from cmd/server).
func (s *Service) SetEmitter(e EventEmitter) { s.emitter = e }

// Pool exposes the connection pool for the handler's audit writes.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) emit(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) {
	if s.emitter == nil {
		return
	}
	_ = s.emitter(ctx, tenantID, eventType, payload) // best-effort
}

// AgentStatus returns an agent's current lifecycle status. Used by the auth
// middleware to deny suspended/decommissioned agents' tokens on every request.
func (s *Service) AgentStatus(ctx context.Context, agentID uuid.UUID) (string, error) {
	var status string
	err := s.pool.QueryRow(ctx, `SELECT status FROM auth.agents WHERE id = $1`, agentID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrNotFound
	}
	return status, err
}

// agentTransitions maps a target status to the source statuses it may come from.
var agentTransitions = map[string][]string{
	"suspended":      {"active"},              // suspend
	"active":         {"suspended"},           // resume
	"decommissioned": {"active", "suspended"}, // terminal
}

// transitionEvent maps a target status to its webhook/audit event verb.
var transitionEvent = map[string]string{
	"active":         "resumed",
	"suspended":      "suspended",
	"decommissioned": "decommissioned",
}

// validateTransition reports whether an agent may move from cur to target.
// Pure (no I/O) so it is unit-testable. A no-op (cur == target) is allowed.
func validateTransition(cur, target string) error {
	froms, ok := agentTransitions[target]
	if !ok {
		return errs.ErrBadRequest.WithDetail("invalid target status")
	}
	if cur == target {
		return nil // idempotent
	}
	if cur == "decommissioned" {
		return errs.ErrConflict.WithDetail("agent is decommissioned (terminal)")
	}
	if slices.Contains(froms, cur) {
		return nil
	}
	return errs.ErrConflict.WithDetail(fmt.Sprintf("cannot move agent from %s to %s", cur, target))
}

// transition moves an agent to target after enforcing the allowed source
// states. Returns the previous status. Emits a webhook event (best-effort) on a
// real change. disabled_at is kept in sync for legacy readers.
func (s *Service) transition(ctx context.Context, id, tenantID uuid.UUID, target string) (string, error) {
	var cur string
	err := s.pool.QueryRow(ctx,
		`SELECT status FROM auth.agents WHERE id = $1 AND tenant_id = $2`, id, tenantID).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if verr := validateTransition(cur, target); verr != nil {
		return cur, verr
	}
	if cur == target {
		return cur, nil // no-op
	}
	disabledAt := "NOW()"
	if target == "active" {
		disabledAt = "NULL"
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE auth.agents SET status = $1, disabled_at = `+disabledAt+` WHERE id = $2 AND tenant_id = $3`,
		target, id, tenantID); err != nil {
		return cur, err
	}
	s.emit(ctx, tenantID, "agent."+transitionEvent[target], map[string]any{
		"agent_id": id.String(), "tenant_id": tenantID.String(),
		"previous_status": cur, "status": target,
	})
	return cur, nil
}

// Suspend, Resume and Decommission are the public lifecycle transitions.
func (s *Service) Suspend(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "suspended")
}
func (s *Service) Resume(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "active")
}
func (s *Service) Decommission(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "decommissioned")
}

type Agent struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Scopes          []string  `json:"scopes"`
	TokenTTLSeconds int       `json:"token_ttl_seconds"`
	// Status is the lifecycle state: active | suspended | decommissioned.
	Status string `json:"status"`
	// Disabled is retained for back-compat (true when Status != "active").
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
	// Secret is the plaintext credential, returned only once on create.
	Secret string `json:"secret,omitempty"`
}

// clampTTL keeps agent token lifetimes short (ephemeral): 60s..1h, default 10m.
func clampTTL(s int) int {
	if s <= 0 {
		return 600
	}
	if s < 60 {
		return 60
	}
	if s > 3600 {
		return 3600
	}
	return s
}

func newSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "agt_" + hex.EncodeToString(b), nil
}

func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, ttl int) (*Agent, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("name is required")
	}
	if scopes == nil {
		scopes = []string{}
	}
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, err
	}
	ttl = clampTTL(ttl)
	var a Agent
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.agents (tenant_id, name, secret_hash, scopes, token_ttl_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, scopes, token_ttl_seconds, created_at
	`, tenantID, name, hash, scopes, ttl).Scan(&a.ID, &a.Name, &a.Scopes, &a.TokenTTLSeconds, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	a.Status = "active" // DB default on insert
	a.Secret = secret
	return &a, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Agent, error) {
	// Decommissioned agents are terminal and excluded from listings.
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, scopes, token_ttl_seconds, status, created_at
		FROM auth.agents WHERE tenant_id = $1 AND status <> 'decommissioned' ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Agent, 0)
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.Scopes, &a.TokenTTLSeconds, &a.Status, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Disabled = a.Status != "active"
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM auth.agents WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// KillAll suspends every active agent for a tenant in one statement (security
// incident response). Returns the number suspended and emits a single
// kill-switch webhook event.
func (s *Service) KillAll(ctx context.Context, tenantID uuid.UUID) (int, error) {
	ct, err := s.pool.Exec(ctx,
		`UPDATE auth.agents SET status = 'suspended', disabled_at = NOW() WHERE tenant_id = $1 AND status = 'active'`,
		tenantID)
	if err != nil {
		return 0, err
	}
	n := int(ct.RowsAffected())
	if n > 0 {
		s.emit(ctx, tenantID, "agent.kill_switch", map[string]any{
			"tenant_id": tenantID.String(), "suspended": n,
		})
	}
	return n, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// IssueToken authenticates an agent (id + secret) and mints a short-lived,
// scoped access token carrying actor_type="agent" + agent_id.
func (s *Service) IssueToken(ctx context.Context, agentID, secret string) (*TokenResponse, error) {
	id, err := uuid.Parse(agentID)
	if err != nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid agent_id")
	}
	var (
		tenantID   uuid.UUID
		secretHash string
		scopes     []string
		ttl        int
		status     string
	)
	err = s.pool.QueryRow(ctx, `
		SELECT tenant_id, secret_hash, scopes, token_ttl_seconds, status
		FROM auth.agents WHERE id = $1
	`, id).Scan(&tenantID, &secretHash, &scopes, &ttl, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown agent")
	}
	if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, errs.ErrUnauthorized.WithDetail("agent " + status)
	}
	if !password.Verify(secretHash, secret) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid agent secret")
	}

	now := time.Now().UTC()
	exp := now.Add(time.Duration(clampTTL(ttl)) * time.Second)
	scope := strings.Join(scopes, " ")

	// Mirror the service-principal token shape (same issuer/audience so it
	// verifies on the standard path) but mark actor_type="agent" + agent_id.
	type agentClaims struct {
		TenantID  uuid.UUID `json:"tenant_id"`
		Scope     string    `json:"scope,omitempty"`
		ActorType string    `json:"actor_type"`
		AgentID   string    `json:"agent_id"`
		jwt.RegisteredClaims
	}
	claims := agentClaims{
		TenantID:  tenantID,
		Scope:     scope,
		ActorType: "agent",
		AgentID:   id.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer.JWTIssuer(),
			Audience:  jwt.ClaimStrings{s.issuer.JWTAudience()},
			Subject:   id.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	signed, err := s.issuer.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &TokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(exp).Seconds()),
		Scope:       scope,
	}, nil
}

// --- handlers ---

type Handler struct {
	Service *Service
}

// Mount registers tenant-scoped admin endpoints (require a user JWT/API key).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/agents", h.list)
	r.Post("/tenants/{tenantID}/agents", h.create)
	r.Post("/tenants/{tenantID}/agents/kill-all", h.killAll)
	r.Delete("/tenants/{tenantID}/agents/{id}", h.del)
	r.Patch("/tenants/{tenantID}/agents/{id}", h.patch)
	r.Post("/tenants/{tenantID}/agents/{id}/suspend", h.suspend)
	r.Post("/tenants/{tenantID}/agents/{id}/resume", h.resume)
	r.Post("/tenants/{tenantID}/agents/{id}/decommission", h.decommission)
}

// auditTransition records an audit row for an agent lifecycle change.
func (h *Handler) auditTransition(r *http.Request, tenantID, agentID uuid.UUID, action, prev, next string) {
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	tid, aid := tenantID, agentID
	_ = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		Action:       action,
		ResourceType: "agent",
		ResourceID:   &aid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"previous_status": prev, "status": next},
	})
	_ = tx.Commit(ctx)
}

// MountPublic registers the agent token endpoint (agent-authenticated, no user
// session) — lives in the public group and is CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/agents/token", h.token)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name            string   `json:"name"`
		Scopes          []string `json:"scopes"`
		TokenTTLSeconds int      `json:"token_ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a, err := h.Service.Create(r.Context(), tenantID, in.Name, in.Scopes, in.TokenTTLSeconds)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Back-compat: PATCH {disabled} maps onto the lifecycle state machine.
	target, action, next := "active", "agent.resumed", "active"
	if in.Disabled {
		target, action, next = "suspended", "agent.suspended", "suspended"
	}
	var prev string
	switch target {
	case "suspended":
		prev, err = h.Service.Suspend(r.Context(), id, tenantID)
	case "active":
		prev, err = h.Service.Resume(r.Context(), id, tenantID)
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditTransition(r, tenantID, id, action, prev, next)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) suspend(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "suspended", "agent.suspended", "suspended")
}
func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "active", "agent.resumed", "active")
}
func (h *Handler) decommission(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "decommissioned", "agent.decommissioned", "decommissioned")
}

// doTransition runs one lifecycle transition, audits it, and returns the new status.
func (h *Handler) doTransition(w http.ResponseWriter, r *http.Request, target, action, next string) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var prev string
	switch target {
	case "suspended":
		prev, err = h.Service.Suspend(r.Context(), id, tenantID)
	case "active":
		prev, err = h.Service.Resume(r.Context(), id, tenantID)
	case "decommissioned":
		prev, err = h.Service.Decommission(r.Context(), id, tenantID)
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditTransition(r, tenantID, id, action, prev, next)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": next})
}

func (h *Handler) killAll(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.KillAll(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditKillSwitch(r, tenantID, n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"suspended": n})
}

// auditKillSwitch records the tenant-wide kill-switch action.
func (h *Handler) auditKillSwitch(r *http.Request, tenantID uuid.UUID, suspended int) {
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	tid := tenantID
	_ = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		Action:       "agent.kill_switch",
		ResourceType: "agent",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"suspended": suspended},
	})
	_ = tx.Commit(ctx)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	}
	// Also accept HTTP Basic (agent_id:secret), mirroring OAuth client auth.
	if u, p, ok := r.BasicAuth(); ok {
		in.AgentID, in.Secret = u, p
	} else if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.Service.IssueToken(r.Context(), in.AgentID, in.Secret)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
