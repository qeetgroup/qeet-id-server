// Package agent provides non-human AI-agent identities: they authenticate with a
// secret and receive short-lived, scoped tokens (actor_type="agent") that are
// re-minted rather than refreshed, yet verify on the standard JWKS/RequireAuth path.
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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agents/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// EventEmitter enqueues a webhook event for a tenant. Injected (webhook service)
// so this package needn't import webhooks. nil = no-op.
type EventEmitter func(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error

type Service struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	issuer  *tokens.Issuer
	emitter EventEmitter
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

// SetEmitter sets the webhook event emitter; nil emits nothing.
func (s *Service) SetEmitter(e EventEmitter) { s.emitter = e }

// Pool exposes the connection pool for the handler's audit writes.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) emit(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) {
	if s.emitter == nil {
		return
	}
	_ = s.emitter(ctx, tenantID, eventType, payload) // best-effort
}

// AgentStatus returns an agent's current lifecycle status, or ErrAgentNotFound.
func (s *Service) AgentStatus(ctx context.Context, agentID uuid.UUID) (string, error) {
	status, err := s.q.GetAgentStatusByID(ctx, agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrAgentNotFound
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
		return errs.ErrAgentStatusInvalid
	}
	if cur == target {
		return nil
	}
	if cur == "decommissioned" {
		return errs.ErrAgentDecommissioned
	}
	if slices.Contains(froms, cur) {
		return nil
	}
	return errs.ErrAgentTransitionInvalid
}

// transition moves an agent to target after enforcing the allowed source
// states. Returns the previous status. Emits a webhook event (best-effort) on a
// real change. disabled_at is kept in sync for legacy readers.
func (s *Service) transition(ctx context.Context, id, tenantID uuid.UUID, target string, actor audit.Actor) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var cur string
	err = tx.QueryRow(ctx, `
		SELECT status FROM auth.agents WHERE id = $1 AND tenant_id = $2 FOR UPDATE
	`, id, tenantID).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrAgentNotFound
	}
	if err != nil {
		return "", err
	}
	if verr := validateTransition(cur, target); verr != nil {
		return cur, verr
	}
	if cur == target {
		return cur, nil
	}
	// Resume clears disabled_at; other transitions stamp disabled_at=NOW().
	qtx := s.q.WithTx(tx)
	if target == "active" {
		err = qtx.ResumeAgent(ctx, dbgen.ResumeAgentParams{ID: id, TenantID: tenantID})
	} else {
		err = qtx.DeactivateAgent(ctx, dbgen.DeactivateAgentParams{Status: target, ID: id, TenantID: tenantID})
	}
	if err != nil {
		return cur, err
	}
	eventType := "agent." + transitionEvent[target]
	payload := map[string]any{
		"agent_id": id.String(), "tenant_id": tenantID.String(),
		"previous_status": cur, "status": target,
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, eventType, "agent", id,
		map[string]any{"previous_status": cur, "status": target})); err != nil {
		return cur, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "agent.events", EventType: eventType, Payload: payload}); err != nil {
		return cur, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cur, err
	}
	s.emit(ctx, tenantID, eventType, payload)
	return cur, nil
}

// Suspend, Resume and Decommission are the public lifecycle transitions.
func (s *Service) Suspend(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "suspended", audit.Actor{Type: "system"})
}
func (s *Service) Resume(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "active", audit.Actor{Type: "system"})
}
func (s *Service) Decommission(ctx context.Context, id, tenantID uuid.UUID) (string, error) {
	return s.transition(ctx, id, tenantID, "decommissioned", audit.Actor{Type: "system"})
}

func (s *Service) TransitionWithActor(ctx context.Context, id, tenantID uuid.UUID, target string, actor audit.Actor) (string, error) {
	return s.transition(ctx, id, tenantID, target, actor)
}

// Agent is an AI-agent identity. Status is active, suspended or decommissioned;
// Disabled mirrors Status != "active" for older clients. SponsorUserID is the
// person accountable for it (required for new agents, nil on older ones), and
// Secret, the plaintext credential, is returned only on create.
type Agent struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Scopes          []string   `json:"scopes"`
	TokenTTLSeconds int        `json:"token_ttl_seconds"`
	Status          string     `json:"status"`
	Disabled        bool       `json:"disabled"`
	SponsorUserID   *uuid.UUID `json:"sponsor_user_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Secret          string     `json:"secret,omitempty"`
}

// pgUUID converts a non-nil uuid.UUID to pgtype.UUID for sqlc params.
func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: true}
}

// uuidFromPg converts a pgtype.UUID to *uuid.UUID (nil when not valid).
func uuidFromPg(p pgtype.UUID) *uuid.UUID {
	if !p.Valid {
		return nil
	}
	id := uuid.UUID(p.Bytes)
	return &id
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

// sponsorBelongsToTenant reports whether userID holds a role in tenantID: a
// sponsor must be an accountable member of the tenant, not just any user.
func (s *Service) sponsorBelongsToTenant(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	return s.q.SponsorBelongsToTenant(ctx, dbgen.SponsorBelongsToTenantParams{
		UserID:   userID,
		TenantID: tenantID,
	})
}

func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, ttl int, sponsorUserID uuid.UUID) (*Agent, error) {
	return s.CreateWithActor(ctx, tenantID, name, scopes, ttl, sponsorUserID, audit.Actor{Type: "system"})
}

func (s *Service) CreateWithActor(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, ttl int, sponsorUserID uuid.UUID, actor audit.Actor) (*Agent, error) {
	if err := rbac.ValidateMachineScopes(scopes); err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, errs.ErrAgentNameRequired
	}
	if sponsorUserID == uuid.Nil {
		return nil, errs.ErrAgentSponsorRequired
	}
	if ok, err := s.sponsorBelongsToTenant(ctx, tenantID, sponsorUserID); err != nil {
		return nil, err
	} else if !ok {
		return nil, errs.ErrAgentSponsorNotMember
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateAgent(ctx, dbgen.CreateAgentParams{
		TenantID:        tenantID,
		Name:            name,
		SecretHash:      hash,
		Scopes:          scopes,
		TokenTtlSeconds: int32(ttl),
		SponsorUserID:   pgUUID(sponsorUserID),
	})
	if err != nil {
		return nil, err
	}
	a := &Agent{
		ID:              row.ID,
		Name:            row.Name,
		Scopes:          row.Scopes,
		TokenTTLSeconds: int(row.TokenTtlSeconds),
		SponsorUserID:   uuidFromPg(row.SponsorUserID),
		CreatedAt:       row.CreatedAt,
		Status:          "active", // DB default on insert
		Secret:          secret,
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "agent.created", "agent", a.ID,
		map[string]any{"name": a.Name, "scopes": a.Scopes, "sponsor_user_id": sponsorUserID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: a.ID, Topic: "agent.events", EventType: "agent.created",
		Payload: map[string]any{
			"agent_id": a.ID, "tenant_id": tenantID, "name": a.Name,
			"scopes": a.Scopes, "sponsor_user_id": sponsorUserID,
		},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Agent, error) {
	// Decommissioned agents are terminal and excluded from listings.
	rows, err := s.q.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, row := range rows {
		out = append(out, Agent{
			ID:              row.ID,
			Name:            row.Name,
			Scopes:          row.Scopes,
			TokenTTLSeconds: int(row.TokenTtlSeconds),
			Status:          row.Status,
			Disabled:        row.Status != "active",
			SponsorUserID:   uuidFromPg(row.SponsorUserID),
			CreatedAt:       row.CreatedAt,
		})
	}
	return out, nil
}

// AgentsSponsoredBy lists a tenant's (non-decommissioned) agents sponsored by
// userID — what an admin needs to see before offboarding that person, so no
// agent is left with an owner who no longer has access.
func (s *Service) AgentsSponsoredBy(ctx context.Context, tenantID, userID uuid.UUID) ([]Agent, error) {
	rows, err := s.q.ListAgentsSponsoredBy(ctx, dbgen.ListAgentsSponsoredByParams{
		TenantID: tenantID,
		UserID:   pgUUID(userID),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, row := range rows {
		out = append(out, Agent{
			ID:              row.ID,
			Name:            row.Name,
			Scopes:          row.Scopes,
			TokenTTLSeconds: int(row.TokenTtlSeconds),
			Status:          row.Status,
			Disabled:        row.Status != "active",
			SponsorUserID:   uuidFromPg(row.SponsorUserID),
			CreatedAt:       row.CreatedAt,
		})
	}
	return out, nil
}

// TransferSponsor reassigns, in one statement, every agent fromUserID sponsors
// in tenantID to toUserID, who must be a tenant member, and returns how many
// moved. Run it before removing fromUserID's access when offboarding.
func (s *Service) TransferSponsor(ctx context.Context, tenantID, fromUserID, toUserID uuid.UUID) (int, error) {
	return s.TransferSponsorWithActor(ctx, tenantID, fromUserID, toUserID, audit.Actor{Type: "system"})
}

func (s *Service) TransferSponsorWithActor(ctx context.Context, tenantID, fromUserID, toUserID uuid.UUID, actor audit.Actor) (int, error) {
	if toUserID == uuid.Nil {
		return 0, errs.ErrAgentSponsorRequired
	}
	if ok, err := s.sponsorBelongsToTenant(ctx, tenantID, toUserID); err != nil {
		return 0, err
	} else if !ok {
		return 0, errs.ErrAgentSponsorNotMember
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).TransferAgentSponsor(ctx, dbgen.TransferAgentSponsorParams{
		ToUserID:   pgUUID(toUserID),
		TenantID:   tenantID,
		FromUserID: pgUUID(fromUserID),
	})
	if err != nil {
		return 0, err
	}
	count := int(n)
	metadata := map[string]any{"from_user_id": fromUserID, "to_user_id": toUserID, "count": count}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "agent.sponsor_transferred", "user", fromUserID, metadata)); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: tenantID, Topic: "agent.events", EventType: "agent.sponsor_transferred",
		Payload: map[string]any{"tenant_id": tenantID, "from_user_id": fromUserID, "to_user_id": toUserID, "count": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if count > 0 {
		s.emit(ctx, tenantID, "agent.sponsor_transferred", map[string]any{
			"tenant_id": tenantID.String(), "from_user_id": fromUserID.String(), "to_user_id": toUserID.String(), "count": count,
		})
	}
	return count, nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.DeleteWithActor(ctx, id, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) DeleteWithActor(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteAgent(ctx, dbgen.DeleteAgentParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAgentNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "agent.deleted", "agent", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id, Topic: "agent.events", EventType: "agent.deleted",
		Payload: map[string]any{"agent_id": id, "tenant_id": tenantID},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// KillAll suspends every active agent for a tenant in one statement (security
// incident response). Returns the number suspended and emits a single
// kill-switch webhook event.
func (s *Service) KillAll(ctx context.Context, tenantID uuid.UUID) (int, error) {
	return s.KillAllWithActor(ctx, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) KillAllWithActor(ctx context.Context, tenantID uuid.UUID, actor audit.Actor) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).KillAllAgents(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	count := int(n)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "agent.kill_switch", "tenant", tenantID,
		map[string]any{"suspended": count})); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: tenantID, Topic: "agent.events", EventType: "agent.kill_switch",
		Payload: map[string]any{"tenant_id": tenantID, "suspended": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if count > 0 {
		s.emit(ctx, tenantID, "agent.kill_switch", map[string]any{
			"tenant_id": tenantID.String(), "suspended": count,
		})
	}
	return count, nil
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
		return nil, errs.ErrAgentTokenInvalid
	}
	row, err := s.q.GetAgentForToken(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAgentTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.Status != "active" {
		return nil, errs.ErrAgentInactive
	}
	if !password.Verify(row.SecretHash, secret) {
		return nil, errs.ErrAgentTokenInvalid
	}

	now := time.Now().UTC()
	exp := now.Add(time.Duration(clampTTL(int(row.TokenTtlSeconds))) * time.Second)
	scope := strings.Join(row.Scopes, " ")

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
		TenantID:  row.TenantID,
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

type Handler struct {
	Service *Service
}

func actorOf(r *http.Request) audit.Actor {
	actor := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if principal := httpx.PrincipalFromCtx(r.Context()); principal != nil {
		actor.UserID = principal.UserID
		if principal.ActorType != "" {
			actor.Type = principal.ActorType
		}
	}
	return actor
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
	r.Get("/tenants/{tenantID}/agents/sponsored-by/{userID}", h.sponsoredBy)
	r.Post("/tenants/{tenantID}/agents/sponsored-by/{userID}/transfer", h.transferSponsor)
}

// MountPublic registers the agent token endpoint (agent-authenticated, no user
// session) — lives in the public group and is CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/agents/token", h.token)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrAgentInvalidID
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrAgentTenantMismatch
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
		Name            string    `json:"name"`
		Scopes          []string  `json:"scopes"`
		TokenTTLSeconds int       `json:"token_ttl_seconds"`
		SponsorUserID   uuid.UUID `json:"sponsor_user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a, err := h.Service.CreateWithActor(r.Context(), tenantID, in.Name, in.Scopes, in.TokenTTLSeconds, in.SponsorUserID, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a)
}

func (h *Handler) sponsoredBy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
		return
	}
	out, err := h.Service.AgentsSponsoredBy(r.Context(), tenantID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) transferSponsor(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	fromUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
		return
	}
	var in struct {
		ToUserID uuid.UUID `json:"to_user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.TransferSponsorWithActor(r.Context(), tenantID, fromUserID, in.ToUserID, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"transferred": n})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
		return
	}
	if err := h.Service.DeleteWithActor(r.Context(), id, tenantID, actorOf(r)); err != nil {
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
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
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
	target := "active"
	if in.Disabled {
		target = "suspended"
	}
	_, err = h.Service.TransitionWithActor(r.Context(), id, tenantID, target, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) suspend(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "suspended")
}
func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "active")
}
func (h *Handler) decommission(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "decommissioned")
}

// doTransition runs one lifecycle transition, audits it, and returns the new status.
func (h *Handler) doTransition(w http.ResponseWriter, r *http.Request, target string) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAgentInvalidID)
		return
	}
	_, err = h.Service.TransitionWithActor(r.Context(), id, tenantID, target, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": target})
}

func (h *Handler) killAll(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.KillAllWithActor(r.Context(), tenantID, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"suspended": n})
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
