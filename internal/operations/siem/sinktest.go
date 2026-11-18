package siem

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestResult is how a destination answered one test event.
type TestResult struct {
	Delivered  bool   `json:"delivered"`
	Status     int    `json:"status,omitempty"` // the collector's HTTP status; absent when it gave none
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Test sends one test event to a destination that isn't saved, after the
// checks Create makes, and reports how it answered.
func (s *Service) Test(ctx context.Context, organizationID uuid.UUID, typ, endpoint, token string, actor audit.Actor) (*TestResult, error) {
	if !validType(typ) {
		return nil, ErrSinkTypeInvalid
	}
	if _, err := s.egress.ValidateHTTPURL(endpoint); err != nil {
		return nil, ErrEndpointInvalid
	}
	return s.test(ctx, organizationID, nil, typ, endpoint, token, actor)
}

// TestSaved sends one test event to one of the organization's destinations and
// reports how it answered. It changes nothing on the destination.
func (s *Service) TestSaved(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) (*TestResult, error) {
	r, err := s.q.GetLogSinkSecret(ctx, dbgen.GetLogSinkSecretParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.box.Open(r.OrganizationID, "siem-token", r.ID.String(), r.TokenCt, r.TokenNonce)
	if err != nil {
		return nil, err
	}
	return s.test(ctx, organizationID, &id, r.Type, r.Endpoint, string(plain), actor)
}

// test sends the test event and audits that it was sent, and how it went.
func (s *Service) test(ctx context.Context, organizationID uuid.UUID, sinkID *uuid.UUID, typ, endpoint, token string, actor audit.Actor) (*TestResult, error) {
	event := AuditEvent{
		ID: uuid.NewString(), OrganizationID: organizationID.String(), ActorType: "system", Action: "siem.test",
		ResourceType: "log_sink", CreatedAt: time.Now().UTC(),
		Metadata: json.RawMessage(`{"test":true,"message":"A test event from Qeet ID; nothing happened."}`),
	}
	body, headers, err := buildRequest(typ, token, []AuditEvent{event})
	if err != nil {
		return nil, err
	}
	start := time.Now()
	status, sendErr := s.send(ctx, endpoint, headers, body)
	res := &TestResult{Delivered: sendErr == nil, Status: status, DurationMS: time.Since(start).Milliseconds()}
	if sendErr != nil {
		res.Error = sendErr.Error()
	}
	if err := audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "siem.sink_tested", "log_sink", postgres.ZeroIfNull(sinkID), map[string]any{
		"type": typ, "delivered": res.Delivered, "status": status, "saved": sinkID != nil,
	})); err != nil {
		return nil, err
	}
	return res, nil
}
