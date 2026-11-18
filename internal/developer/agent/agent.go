// Package agent provides non-human AI-agent identities: they authenticate with a
// secret and receive short-lived, scoped tokens (actor_type="agent") that are
// re-minted rather than refreshed, yet verify on the standard JWKS/RequireAuth path.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agent/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service manages the agents. Its events go out through the outbox, and so
// reach webhooks too.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

// NewService returns the agent service.
func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

// AgentStatus returns an agent's current lifecycle status, or ErrAgentNotFound.
func (s *Service) AgentStatus(ctx context.Context, agentID uuid.UUID) (string, error) {
	status, err := s.q.GetAgentStatusByID(ctx, agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrAgentNotFound
	}
	return status, err
}

// Agent is an AI-agent identity. Status is active, suspended or decommissioned (Disabled mirrors
// Status != "active" for older clients). SponsorUserID is the accountable person (nil only on older
// agents); Secret is returned only on create. LastUsedAt is its last token, to the minute;
// PreviousSecretExpiresAt is when the secret replaced at its last rotation stops working.
type Agent struct {
	ID                      uuid.UUID  `json:"id"`
	Name                    string     `json:"name"`
	Scopes                  []string   `json:"scopes"`
	TokenTTLSeconds         int        `json:"token_ttl_seconds"`
	Status                  string     `json:"status"`
	Disabled                bool       `json:"disabled"`
	SponsorUserID           *uuid.UUID `json:"sponsor_user_id,omitempty"`
	LastUsedAt              *time.Time `json:"last_used_at"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	Secret                  string     `json:"secret,omitempty"`
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

// Create registers an agent in organizationID with its scopes, token lifetime in
// seconds and sponsor, who must be an organization member, recorded as actor's. The
// returned Agent carries its plaintext secret, shown only now.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, name string, scopes []string, ttl int, sponsorUserID uuid.UUID, actor audit.Actor) (*Agent, error) {
	if err := rbac.ValidateMachineScopes(scopes); err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, ErrNameRequired
	}
	if sponsorUserID == uuid.Nil {
		return nil, ErrSponsorRequired
	}
	if ok, err := s.sponsorBelongsToOrganization(ctx, organizationID, sponsorUserID); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrSponsorNotMember
	}
	if scopes == nil {
		scopes = []string{}
	}
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	hash := password.HashSecret(secret)
	ttl = clampTTL(ttl)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateAgent(ctx, dbgen.CreateAgentParams{
		OrganizationID:  organizationID,
		Name:            name,
		SecretHash:      hash,
		Scopes:          scopes,
		TokenTtlSeconds: int32(ttl), // #nosec G115 -- clamped to 60–3600 by clampTTL
		SponsorUserID:   &sponsorUserID,
	})
	if err != nil {
		return nil, err
	}
	a := &Agent{
		ID:              row.ID,
		Name:            row.Name,
		Scopes:          row.Scopes,
		TokenTTLSeconds: int(row.TokenTtlSeconds),
		SponsorUserID:   row.SponsorUserID,
		CreatedAt:       row.CreatedAt,
		Status:          "active", // DB default on insert
		Secret:          secret,
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.created", "agent", a.ID,
		map[string]any{"name": a.Name, "scopes": a.Scopes, "sponsor_user_id": sponsorUserID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: a.ID, Topic: "agent.events", EventType: "agent.created",
		Payload: map[string]any{
			"agent_id": a.ID, "organization_id": organizationID, "name": a.Name,
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

// List returns the organization's agents.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Agent, error) {
	// Decommissioned agents are terminal and excluded from listings.
	rows, err := s.q.ListAgents(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, row := range rows {
		a := Agent{
			ID:              row.ID,
			Name:            row.Name,
			Scopes:          row.Scopes,
			TokenTTLSeconds: int(row.TokenTtlSeconds),
			Status:          row.Status,
			Disabled:        row.Status != "active",
			SponsorUserID:   row.SponsorUserID,
			LastUsedAt:      row.LastUsedAt,
			CreatedAt:       row.CreatedAt,
		}
		if until := row.PreviousSecretExpiresAt; until != nil && until.After(time.Now()) {
			a.PreviousSecretExpiresAt = until
		}
		out = append(out, a)
	}
	return out, nil
}

// Delete removes one of the organization's agents, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteAgent(ctx, dbgen.DeleteAgentParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAgentNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.deleted", "agent", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id, Topic: "agent.events", EventType: "agent.deleted",
		Payload: map[string]any{"agent_id": id, "organization_id": organizationID},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ClientCredentials authenticates agent clientID by its secret at the
// client_credentials grant and mints its short-lived, scoped access token.
// known is false, with no error, when clientID names no agent of an active
// organization.
func (s *Service) ClientCredentials(ctx context.Context, clientID, secret string) (*tokens.MachineToken, bool, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, false, nil //nolint:nilerr // an id that isn't a UUID names no agent
	}
	row, err := s.q.GetAgentForToken(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	// The secret first, so only its holder learns the agent's status.
	if !password.VerifySecret(row.SecretHash, secret) && !rotation.PreviousSecretWorks(row.PreviousSecretHash, row.PreviousSecretExpiresAt, secret) {
		return nil, true, errs.ErrAgentTokenInvalid
	}
	if row.Status != "active" {
		return nil, true, errs.ErrAgentInactive
	}
	if err := s.q.TouchAgent(ctx, dbgen.TouchAgentParams{ID: id, OrganizationID: row.OrganizationID}); err != nil {
		slog.Warn("agent last use not recorded", "err", err, "agent_id", id)
	}
	tok, err := s.issuer.IssueMachineAccess(tokens.MachineAccess{
		Subject: id, OrganizationID: row.OrganizationID, Scopes: row.Scopes, Agent: true,
		TTL: time.Duration(clampTTL(int(row.TokenTtlSeconds))) * time.Second,
	})
	return tok, true, err
}
