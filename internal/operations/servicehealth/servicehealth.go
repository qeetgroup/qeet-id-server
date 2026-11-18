// Package servicehealth tells an organization the state of each part of the
// service it uses (the API, sign-in, email, webhooks and directories) and the
// incidents operators have posted. A part's state comes from the
// organization's own recent figures, made worse by any incident still open.
package servicehealth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/servicehealth/dbgen"
)

// Components, in the order they are reported.
const (
	ComponentAPI       = "api"
	ComponentSignIn    = "sign_in"
	ComponentEmail     = "email"
	ComponentWebhooks  = "webhooks"
	ComponentDirectory = "directory"
)

// States, from best to worst; NotConfigured is a part the organization doesn't use.
const (
	StateNotConfigured = "not_configured"
	StateOperational   = "operational"
	StateMaintenance   = "maintenance"
	StateDegraded      = "degraded"
	StateOutage        = "outage"
)

var stateRank = map[string]int{
	StateNotConfigured: 0, StateOperational: 1, StateMaintenance: 2, StateDegraded: 3, StateOutage: 4,
}

// worse returns the worse of two states.
func worse(a, b string) string {
	if stateRank[b] > stateRank[a] {
		return b
	}
	return a
}

// Component is one part of the service. Reason says why it isn't operational:
// a code such as email.failing, or incident when an open incident is the cause.
// Figures are the counts its state was judged by.
type Component struct {
	Name    string         `json:"name"`
	State   string         `json:"state"`
	Reason  string         `json:"reason,omitempty"`
	Figures map[string]int `json:"figures,omitempty"`
}

// Incident is a problem or maintenance an operator posted. ResolvedAt is nil
// while it lasts.
type Incident struct {
	ID         uuid.UUID  `json:"id"`
	Component  string     `json:"component"`
	Impact     string     `json:"impact"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// Report is an organization's view of the service: Status is the worst state
// of its components.
type Report struct {
	Status     string      `json:"status"`
	CheckedAt  time.Time   `json:"checked_at"`
	Components []Component `json:"components"`
	Incidents  []Incident  `json:"incidents"`
}

// Service reads the service's health.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	// SignInReady reports whether tokens can be signed; nil counts as ready.
	SignInReady func(ctx context.Context) error
}

// NewService returns the service-health Service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Report returns the state of each component for organizationID, and the incidents
// open or resolved in the last 14 days.
func (s *Service) Report(ctx context.Context, organizationID uuid.UUID) (*Report, error) {
	api := Component{Name: ComponentAPI, State: StateOperational}
	if err := s.pool.Ping(ctx); err != nil {
		slog.Warn("service health: database unreachable", "err", err)
		api.State, api.Reason = StateOutage, "api.database_unreachable"
	}
	signIn := Component{Name: ComponentSignIn, State: StateOperational}
	if s.SignInReady != nil {
		if err := s.SignInReady(ctx); err != nil {
			slog.Warn("service health: signing keys unavailable", "err", err)
			signIn.State, signIn.Reason = StateOutage, "sign_in.keys_unavailable"
		}
	}
	email, err := s.email(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	webhooks, err := s.webhooks(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	directory, err := s.directory(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.RecentIncidents(ctx)
	if err != nil {
		return nil, err
	}
	incidents := make([]Incident, 0, len(rows))
	for _, row := range rows {
		in := Incident{ID: row.ID, Component: row.Component, Impact: row.Impact, Title: row.Title,
			Detail: row.Detail, StartedAt: row.StartedAt}
		in.ResolvedAt = row.ResolvedAt
		incidents = append(incidents, in)
	}
	return assemble([]Component{api, signIn, email, webhooks, directory}, incidents, time.Now().UTC()), nil
}

// assemble makes each component no better than its open incidents' impact and
// the report's status the worst of its components.
func assemble(components []Component, incidents []Incident, now time.Time) *Report {
	status := StateOperational
	for i := range components {
		c := &components[i]
		for _, in := range incidents {
			if in.ResolvedAt == nil && in.Component == c.Name && stateRank[in.Impact] > stateRank[c.State] {
				c.State, c.Reason = in.Impact, "incident"
			}
		}
		status = worse(status, c.State)
	}
	return &Report{Status: status, CheckedAt: now, Components: components, Incidents: incidents}
}

// email is degraded when the provider refused at least a quarter of the
// organization's emails of the last hour.
func (s *Service) email(ctx context.Context, organizationID uuid.UUID) (Component, error) {
	row, err := s.q.EmailHealth(ctx, &organizationID)
	if err != nil {
		return Component{}, fmt.Errorf("email health: %w", err)
	}
	c := Component{Name: ComponentEmail, State: StateOperational,
		Figures: map[string]int{"sent_last_hour": int(row.Attempted), "failed_last_hour": int(row.Failed)}}
	if row.Failed > 0 && row.Failed*4 >= row.Attempted {
		c.State, c.Reason = StateDegraded, "email.failing"
	}
	return c, nil
}

// webhooks is degraded while a subscription's deliveries are failing or one
// was disabled for failing, and not configured without an enabled one.
func (s *Service) webhooks(ctx context.Context, organizationID uuid.UUID) (Component, error) {
	row, err := s.q.WebhookHealth(ctx, organizationID)
	if err != nil {
		return Component{}, fmt.Errorf("webhook health: %w", err)
	}
	c := Component{Name: ComponentWebhooks, State: StateOperational, Figures: map[string]int{
		"active": int(row.Active), "failing": int(row.Failing), "disabled_failing": int(row.DisabledFailing),
	}}
	switch {
	case row.Failing > 0 || row.DisabledFailing > 0:
		c.State, c.Reason = StateDegraded, "webhooks.failing"
	case row.Active == 0:
		c.State = StateNotConfigured
	}
	return c, nil
}

// directory is degraded while a directory operation of the last day failed and
// is still open, and not configured without an active LDAP connection or SCIM
// token.
func (s *Service) directory(ctx context.Context, organizationID uuid.UUID) (Component, error) {
	row, err := s.q.DirectoryHealth(ctx, organizationID)
	if err != nil {
		return Component{}, fmt.Errorf("directory health: %w", err)
	}
	c := Component{Name: ComponentDirectory, State: StateOperational, Figures: map[string]int{
		"ldap_connections": int(row.LdapConnections), "scim_tokens": int(row.ScimTokens), "open_failures": int(row.OpenFailures),
	}}
	switch {
	case row.OpenFailures > 0:
		c.State, c.Reason = StateDegraded, "directory.failing"
	case row.LdapConnections == 0 && row.ScimTokens == 0:
		c.State = StateNotConfigured
	}
	return c, nil
}

// OpenIncident posts an incident on component and returns its id.
func (s *Service) OpenIncident(ctx context.Context, component, impact, title, detail string) (uuid.UUID, error) {
	if _, ok := stateRank[impact]; !ok || impact == StateOperational || impact == StateNotConfigured {
		return uuid.Nil, fmt.Errorf("impact %q: want maintenance, degraded or outage", impact)
	}
	switch component {
	case ComponentAPI, ComponentSignIn, ComponentEmail, ComponentWebhooks, ComponentDirectory:
	default:
		return uuid.Nil, fmt.Errorf("component %q: want api, sign_in, email, webhooks or directory", component)
	}
	if title == "" {
		return uuid.Nil, errors.New("an incident needs a title")
	}
	return s.q.OpenIncident(ctx, dbgen.OpenIncidentParams{Component: component, Impact: impact, Title: title, Detail: detail})
}

// ResolveIncident ends an open incident.
func (s *Service) ResolveIncident(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.ResolveIncident(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("incident %s: none open", id)
	}
	return nil
}
