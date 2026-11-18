package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
)

const (
	forwardBatch  = 100              // events per request to a sink
	forwardLease  = 2 * time.Minute  // how long an instance holds a sink; a crashed one's lapses
	forwardBudget = 30 * time.Second // one sink's round of batches, so a busy one doesn't hold up the rest
)

var (
	forwardLag = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "siem_forward_lag_seconds",
		Help: "How far behind the audit log the furthest-behind log sink was at the last round, 0 when every sink caught up.",
	})
	forwardFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_forward_failures_total",
		Help: "Batches a log sink refused or couldn't be reached for.",
	})
)

// Run is the background forwarder: every 10 seconds until ctx is done, it sends
// each enabled sink its new events.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := s.forwardDue(ctx); err != nil {
			slog.Warn("siem forward tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

type sinkRow struct {
	id, organizationID uuid.UUID
	typ, endpoint      string
	token              string
}

// forwardDue forwards new events to every enabled sink.
func (s *Service) forwardDue(ctx context.Context) error {
	stored, err := s.q.ListEnabledLogSinks(ctx)
	if err != nil {
		return err
	}

	sinks := make([]sinkRow, 0, len(stored))
	for _, r := range stored {
		plain, openErr := s.box.Open(r.OrganizationID, "siem-token", r.ID.String(), r.TokenCt, r.TokenNonce)
		if openErr != nil {
			return openErr
		}
		sinks = append(sinks, sinkRow{id: r.ID, organizationID: r.OrganizationID, typ: r.Type, endpoint: r.Endpoint, token: string(plain)})
	}
	var lag time.Duration
	for _, sk := range sinks {
		lag = max(lag, s.forwardSink(ctx, sk))
	}
	forwardLag.Set(lag.Seconds())
	return nil
}

// forwardSink sends sk its new events in batches, while they come full and
// within forwardBudget, holding a lease on the sink so no other instance sends
// them too. It returns how far behind the audit log the sink is left, 0 when
// caught up. A sink another instance holds, or one backing off, is skipped.
func (s *Service) forwardSink(ctx context.Context, sk sinkRow) time.Duration {
	claim, err := s.q.ClaimLogSink(ctx, dbgen.ClaimLogSinkParams{ID: sk.id, LeasedUntil: time.Now().Add(forwardLease)})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0
	}
	if err != nil {
		slog.Warn("siem claim sink", "sink", sk.id, "err", err)
		return 0
	}
	defer func() { _ = s.q.ReleaseLogSink(context.WithoutCancel(ctx), sk.id) }()
	// A NULL cursor means "from now", with the zero UUID, as the INSERT
	// default does.
	cursorAt, cursorID := time.Now(), uuid.UUID{}
	if claim.CursorCreatedAt != nil {
		cursorAt = *claim.CursorCreatedAt
	}
	if claim.CursorID != nil {
		cursorID = *claim.CursorID
	}
	deadline := time.Now().Add(forwardBudget)
	for {
		events, lastAt, lastID, err := s.fetchEvents(ctx, sk.organizationID, cursorAt, cursorID)
		if err != nil {
			slog.Warn("siem fetch events", "sink", sk.id, "err", err)
			return 0
		}
		if len(events) == 0 {
			return 0
		}
		body, headers, err := buildRequest(sk.typ, sk.token, events)
		if err == nil {
			err = s.post(ctx, sk.endpoint, headers, body)
		}
		if err != nil {
			forwardFailures.Inc()
			s.recordError(ctx, sk.id, err.Error())
			return time.Since(events[0].CreatedAt)
		}
		// Advance the cursor; on error, the next attempt resends the batch.
		if err := s.q.AdvanceLogSinkCursor(ctx, dbgen.AdvanceLogSinkCursorParams{
			CursorCreatedAt: &lastAt,
			CursorID:        &lastID,
			ID:              sk.id,
		}); err != nil {
			slog.Warn("siem advance cursor", "sink", sk.id, "err", err)
			return time.Since(lastAt)
		}
		cursorAt, cursorID = lastAt, lastID
		if len(events) < forwardBatch {
			return 0
		}
		if time.Now().After(deadline) {
			return time.Since(lastAt)
		}
	}
}

func (s *Service) fetchEvents(ctx context.Context, organizationID uuid.UUID, afterAt time.Time, afterID uuid.UUID) ([]AuditEvent, time.Time, uuid.UUID, error) {
	// audit.events.organization_id is nullable, so it takes a pointer.
	genRows, err := s.q.FetchAuditEventsAfterCursor(ctx, dbgen.FetchAuditEventsAfterCursorParams{
		OrganizationID: &organizationID,
		AfterAt:        afterAt,
		AfterID:        afterID,
		RowLimit:       forwardBatch,
	})
	if err != nil {
		return nil, afterAt, afterID, err
	}
	var (
		out    []AuditEvent
		lastAt = afterAt
		lastID = afterID
	)
	for _, r := range genRows {
		var e AuditEvent
		e.ID = r.ID.String()
		if r.OrganizationID != nil {
			e.OrganizationID = r.OrganizationID.String()
		}
		if r.ActorUserID != nil {
			as := r.ActorUserID.String()
			e.ActorUserID = &as
		}
		e.ActorType = r.ActorType
		e.Action = r.Action
		e.ResourceType = r.ResourceType
		if r.ResourceID != nil {
			rs := r.ResourceID.String()
			e.ResourceID = &rs
		}
		// The query maps a NULL ip to ""; turn that back into nil.
		if r.Host != "" {
			h := r.Host
			e.IP = &h
		}
		// request_id is nullable; nil means none was recorded.
		if r.RequestID != nil {
			e.RequestID = *r.RequestID
		}
		if r.UserAgent != nil {
			e.UserAgent = *r.UserAgent
		}
		if len(r.Metadata) > 0 && string(r.Metadata) != "{}" {
			e.Metadata = r.Metadata
		}
		e.CreatedAt = r.CreatedAt
		out = append(out, e)
		lastAt, lastID = r.CreatedAt, r.ID
	}
	return out, lastAt, lastID, nil
}

func (s *Service) post(ctx context.Context, endpoint string, headers map[string]string, body []byte) error {
	_, err := s.send(ctx, endpoint, headers, body)
	return err
}

// send posts body to endpoint and returns the collector's status, 0 when it
// gave no answer, and an error unless it accepted the body.
func (s *Service) send(ctx context.Context, endpoint string, headers map[string]string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("sink returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (s *Service) recordError(ctx context.Context, id uuid.UUID, msg string) {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_ = s.q.SetLogSinkError(ctx, dbgen.SetLogSinkErrorParams{LastError: msg, ID: id})
}

// buildRequest renders a batch of events into the body and headers the
// collector type expects. It does no I/O.
func buildRequest(sinkType, token string, events []AuditEvent) ([]byte, map[string]string, error) {
	switch sinkType {
	case typeSplunkHEC:
		// HEC accepts back-to-back JSON event envelopes.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, e := range events {
			env := map[string]any{
				"time":       e.CreatedAt.Unix(),
				"source":     "qeet-id",
				"sourcetype": "qeet:audit",
				"event":      e,
			}
			if err := enc.Encode(env); err != nil {
				return nil, nil, err
			}
		}
		h := map[string]string{"Content-Type": "application/json"}
		if token != "" {
			h["Authorization"] = "Splunk " + token
		}
		return buf.Bytes(), h, nil

	case typeDatadog:
		// Datadog logs intake accepts a JSON array of log entries.
		arr := make([]map[string]any, 0, len(events))
		for _, e := range events {
			msg, _ := json.Marshal(e)
			arr = append(arr, map[string]any{
				"ddsource": "qeet-id",
				"service":  "qeet-id",
				"ddtags":   "organization:" + e.OrganizationID,
				"message":  string(msg),
			})
		}
		body, err := json.Marshal(arr)
		if err != nil {
			return nil, nil, err
		}
		h := map[string]string{"Content-Type": "application/json"}
		if token != "" {
			h["DD-API-KEY"] = token
		}
		return body, h, nil

	default: // generic http
		body, err := json.Marshal(map[string]any{"events": events})
		if err != nil {
			return nil, nil, err
		}
		h := map[string]string{"Content-Type": "application/json"}
		if token != "" {
			h["Authorization"] = "Bearer " + token
		}
		return body, h, nil
	}
}
