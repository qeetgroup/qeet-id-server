// Package siem streams a tenant's audit events to an external collector (Splunk
// HEC, Datadog logs, or a generic HTTP endpoint). A background forwarder walks
// audit.events past each sink's high-watermark cursor and POSTs new events.
// Sinks stream from creation time (no history backfill); delivery is
// at-least-once (the cursor only advances on a 2xx).
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	typeSplunkHEC = "splunk_hec"
	typeDatadog   = "datadog"
	typeHTTP      = "http"
)

const forwardBatch = 100

// Sink is a tenant's configured log destination. Token is write-only (never
// serialized back to the API).
type Sink struct {
	ID              uuid.UUID  `json:"id"`
	Type            string     `json:"type"`
	Endpoint        string     `json:"endpoint"`
	Enabled         bool       `json:"enabled"`
	LastForwardedAt *time.Time `json:"last_forwarded_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// AuditEvent is the projection of an audit row that gets forwarded.
type AuditEvent struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Action       string    `json:"action"`
	ActorType    string    `json:"actor_type"`
	ActorUserID  *string   `json:"actor_user_id,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   *string   `json:"resource_id,omitempty"`
	IP           *string   `json:"ip,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{
		pool:   pool,
		q:      dbgen.New(pool),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func validType(t string) bool {
	return t == typeSplunkHEC || t == typeDatadog || t == typeHTTP
}

// Create registers a sink. It starts streaming from now (cursor = creation
// time), so enabling a sink never dumps the entire audit history downstream.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, typ, endpoint, token string) (*Sink, error) {
	if !validType(typ) {
		return nil, errs.ErrUnprocessable.WithDetail("type must be splunk_hec, datadog, or http")
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
		return nil, errs.ErrUnprocessable.WithDetail("endpoint must be an absolute http(s) URL")
	}
	row, err := s.q.InsertLogSink(ctx, dbgen.InsertLogSinkParams{
		TenantID: tenantID, Type: typ, Endpoint: endpoint, Token: token,
	})
	if err != nil {
		return nil, err
	}
	sk := &Sink{
		ID: row.ID, Type: row.Type, Endpoint: row.Endpoint,
		Enabled: row.Enabled, LastError: row.LastError, CreatedAt: row.CreatedAt,
	}
	if row.LastForwardedAt.Valid {
		t := row.LastForwardedAt.Time
		sk.LastForwardedAt = &t
	}
	return sk, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Sink, error) {
	rows, err := s.q.ListLogSinks(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Sink, 0, len(rows))
	for _, r := range rows {
		sk := Sink{
			ID: r.ID, Type: r.Type, Endpoint: r.Endpoint,
			Enabled: r.Enabled, LastError: r.LastError, CreatedAt: r.CreatedAt,
		}
		if r.LastForwardedAt.Valid {
			t := r.LastForwardedAt.Time
			sk.LastForwardedAt = &t
		}
		out = append(out, sk)
	}
	return out, nil
}

func (s *Service) SetEnabled(ctx context.Context, id, tenantID uuid.UUID, enabled bool) error {
	n, err := s.q.SetLogSinkEnabled(ctx, dbgen.SetLogSinkEnabledParams{
		Enabled: enabled, ID: id, TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	n, err := s.q.DeleteLogSink(ctx, dbgen.DeleteLogSinkParams{
		ID: id, TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Run is the background forwarder. It is a no-op when no sinks are enabled.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.forwardDue(ctx); err != nil {
				slog.Warn("siem forward tick", "err", err)
			}
		}
	}
}

type sinkRow struct {
	id, tenantID  uuid.UUID
	typ, endpoint string
	token         string
	cursorAt      time.Time
	cursorID      uuid.UUID
}

func (s *Service) forwardDue(ctx context.Context) error {
	rows, err := s.q.ListEnabledLogSinks(ctx)
	if err != nil {
		return err
	}
	var sinks []sinkRow
	for _, r := range rows {
		sk := sinkRow{
			id: r.ID, tenantID: r.TenantID,
			typ: r.Type, endpoint: r.Endpoint, token: r.Token,
			// Apply COALESCE defaults in Go: null cursor_created_at → NOW(),
			// null cursor_id → zero UUID (matches the INSERT default).
			cursorAt: time.Now(),
			cursorID: uuid.UUID{},
		}
		if r.CursorCreatedAt.Valid {
			sk.cursorAt = r.CursorCreatedAt.Time
		}
		if r.CursorID.Valid {
			sk.cursorID = uuid.UUID(r.CursorID.Bytes)
		}
		sinks = append(sinks, sk)
	}
	for _, sk := range sinks {
		s.forwardSink(ctx, sk)
	}
	return nil
}

func (s *Service) forwardSink(ctx context.Context, sk sinkRow) {
	events, lastAt, lastID, err := s.fetchEvents(ctx, sk.tenantID, sk.cursorAt, sk.cursorID)
	if err != nil {
		slog.Warn("siem fetch events", "sink", sk.id, "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	body, headers, err := buildRequest(sk.typ, sk.token, events)
	if err != nil {
		s.recordError(ctx, sk.id, err.Error())
		return
	}
	if err := s.post(ctx, sk.endpoint, headers, body); err != nil {
		s.recordError(ctx, sk.id, err.Error())
		return
	}
	// Advance the cursor; ignore errors (retry on next tick).
	_ = s.q.AdvanceLogSinkCursor(ctx, dbgen.AdvanceLogSinkCursorParams{
		CursorCreatedAt: pgtype.Timestamptz{Time: lastAt, Valid: true},
		CursorID:        pgtype.UUID{Bytes: lastID, Valid: true},
		ID:              sk.id,
	})
}

func (s *Service) fetchEvents(ctx context.Context, tenantID uuid.UUID, afterAt time.Time, afterID uuid.UUID) ([]AuditEvent, time.Time, uuid.UUID, error) {
	// tenant_id is nullable in audit.events; we always query by a specific tenant.
	genRows, err := s.q.FetchAuditEventsAfterCursor(ctx, dbgen.FetchAuditEventsAfterCursorParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		AfterAt:  afterAt,
		AfterID:  afterID,
		RowLimit: forwardBatch,
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
		if r.TenantID.Valid {
			e.TenantID = uuid.UUID(r.TenantID.Bytes).String()
		}
		if r.ActorUserID.Valid {
			as := uuid.UUID(r.ActorUserID.Bytes).String()
			e.ActorUserID = &as
		}
		e.ActorType = r.ActorType
		e.Action = r.Action
		e.ResourceType = r.ResourceType
		if r.ResourceID.Valid {
			rs := uuid.UUID(r.ResourceID.Bytes).String()
			e.ResourceID = &rs
		}
		// COALESCE(host(ip),'') in the query maps NULL ip to ""; convert back to nil.
		if r.Host != "" {
			h := r.Host
			e.IP = &h
		}
		// request_id is nullable TEXT; nil pointer means no request ID recorded.
		if r.RequestID != nil {
			e.RequestID = *r.RequestID
		}
		e.CreatedAt = r.CreatedAt
		out = append(out, e)
		lastAt, lastID = r.CreatedAt, r.ID
	}
	return out, lastAt, lastID, nil
}

func (s *Service) post(ctx context.Context, endpoint string, headers map[string]string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sink returned %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) recordError(ctx context.Context, id uuid.UUID, msg string) {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_ = s.q.SetLogSinkError(ctx, dbgen.SetLogSinkErrorParams{LastError: msg, ID: id})
}

// buildRequest renders a batch of events into the body + headers each collector
// expects. Pure (no network), so it's unit-testable.
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
				"ddtags":   "tenant:" + e.TenantID,
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

// --- handlers ---

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/log-sinks", h.list)
	r.Post("/tenants/{tenantID}/log-sinks", h.create)
	r.Patch("/tenants/{tenantID}/log-sinks/{id}", h.patch)
	r.Delete("/tenants/{tenantID}/log-sinks/{id}", h.del)
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
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sk, err := h.Service.Create(r.Context(), tenantID, in.Type, in.Endpoint, in.Token)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sk)
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
		Enabled bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.SetEnabled(r.Context(), id, tenantID, in.Enabled); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": in.Enabled})
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
