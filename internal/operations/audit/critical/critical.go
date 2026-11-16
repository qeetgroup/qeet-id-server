// Package critical is the short list an on-call administrator triages from a
// phone: the organisation's open anomaly alerts and its critical audit events
// of the last hours, newest first, read only. Which events are critical, and
// how severe, is decided here, so every client shows the same list. Anything
// deeper (the full trail, search) stays in the console.
package critical

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Levels of a critical event.
const (
	High   = "high"
	Medium = "medium"
)

// Actions are the audit actions that count as critical, with their level:
// someone locked out or stopped, authority or protection taken away.
var Actions = map[string]string{
	"agent.kill_switch":         High,
	"user.suspended":            High,
	"tenant.suspended":          High,
	"auth.account_locked":       High,
	"auth.mfa_locked":           High,
	"mfa.admin_reset":           High,
	"session.admin_revoked_all": High,
	"role.assigned":             Medium,
	"user.reactivated":          Medium,
	"mfa.totp_disabled":         Medium,
	"risk.settings_updated":     Medium,
}

// highAnomalyScore is the score from which an anomaly is high, as the anomaly
// summary counts them.
const highAnomalyScore = 0.85

const (
	defaultHours = 24
	maxHours     = 7 * 24
	maxEvents    = 100
)

// Event is one critical thing that happened.
type Event struct {
	ID           uuid.UUID      `json:"id"`
	Source       string         `json:"source"` // "anomaly" or "audit"
	Level        string         `json:"level"`
	Action       string         `json:"action"`
	ActorUserID  *uuid.UUID     `json:"actor_user_id,omitempty"`
	ActorEmail   *string        `json:"actor_email,omitempty"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID     `json:"resource_id,omitempty"`
	IP           *string        `json:"ip,omitempty"`
	Reasons      []string       `json:"reasons,omitempty"`
	Score        *float64       `json:"score,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

// AuditLister lists audit events (audit.Reader).
type AuditLister interface {
	List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string, filter audit.ListFilter) ([]audit.Row, string, int, error)
}

// AnomalyLister lists anomaly alerts (anomaly.Service).
type AnomalyLister interface {
	List(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]anomaly.Anomaly, error)
}

// Service builds the list.
type Service struct {
	Audit     AuditLister
	Anomalies AnomalyLister
	now       func() time.Time
}

// NewService returns a Service over both sources.
func NewService(a AuditLister, an AnomalyLister) *Service {
	return &Service{Audit: a, Anomalies: an, now: time.Now}
}

// List returns tenantID's open anomalies and critical audit events of the last
// hours (1 to 168), newest first, at most maxEvents+1 so the caller can tell
// when there are more than maxEvents.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, hours int) ([]Event, error) {
	if hours < 1 || hours > maxHours {
		return nil, errs.ErrBadRequest.WithDetail("hours must be 1 to 168")
	}
	since := s.now().Add(-time.Duration(hours) * time.Hour)
	actions := make([]string, 0, len(Actions))
	for a := range Actions {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	rows, _, _, err := s.Audit.List(ctx, tenantID, maxEvents+1, "", audit.ListFilter{Actions: actions, From: &since})
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, Event{
			ID: r.ID, Source: "audit", Level: Actions[r.Action], Action: r.Action,
			ActorUserID: r.ActorUserID, ResourceType: r.ResourceType, ResourceID: r.ResourceID,
			IP: r.IP, Metadata: r.Metadata, OccurredAt: r.CreatedAt,
		})
	}
	open, err := s.Anomalies.List(ctx, tenantID, "open", maxEvents+1)
	if err != nil {
		return nil, err
	}
	for _, a := range open {
		if a.EventAt.Before(since) {
			continue
		}
		level := Medium
		if a.Score >= highAnomalyScore {
			level = High
		}
		score := a.Score
		out = append(out, Event{
			ID: a.ID, Source: "anomaly", Level: level, Action: a.Action,
			ActorUserID: a.ActorUserID, ActorEmail: a.ActorEmail, ResourceType: a.ResourceType,
			IP: a.IP, Reasons: a.Reasons, Score: &score, OccurredAt: a.EventAt,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if len(out) > maxEvents+1 {
		out = out[:maxEvents+1]
	}
	return out, nil
}

// Handler serves GET /v1/tenants/{tenantID}/critical-events.
type Handler struct {
	Service *Service
}

// Mount registers the route on the authenticated /v1 router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/critical-events", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	hours := defaultHours
	if v := r.URL.Query().Get("hours"); v != "" {
		if hours, err = strconv.Atoi(v); err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid hours"))
			return
		}
	}
	out, err := h.Service.List(r.Context(), tid, hours)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	body := map[string]any{"hours": hours}
	if len(out) > maxEvents {
		out = out[:maxEvents]
		body["truncated"] = true
	}
	high := 0
	for _, e := range out {
		if e.Level == High {
			high++
		}
	}
	body["events"], body["high"] = out, high
	httpx.WriteJSON(w, http.StatusOK, body)
}
