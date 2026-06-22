// Package siem streams a tenant's audit events to an external collector
// (Splunk HEC, Datadog logs, or a generic HTTP endpoint). A background
// forwarder walks audit.events past each sink's high-watermark cursor and POSTs
// new events in the collector's expected shape. Sinks start streaming from
// their creation time (no history backfill); delivery is at-least-once (the
// cursor only advances on a 2xx). Everything is inert until a tenant configures
// a sink, so dev/CI/offline are unaffected.
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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
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
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, client: &http.Client{Timeout: 10 * time.Second}}
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
	var sk Sink
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.log_sinks (tenant_id, type, endpoint, token, cursor_created_at, cursor_id)
		VALUES ($1, $2, $3, $4, NOW(), '00000000-0000-0000-0000-000000000000')
		RETURNING id, type, endpoint, enabled, last_forwarded_at, last_error, created_at
	`, tenantID, typ, endpoint, token).Scan(&sk.ID, &sk.Type, &sk.Endpoint, &sk.Enabled, &sk.LastForwardedAt, &sk.LastError, &sk.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sk, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Sink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, type, endpoint, enabled, last_forwarded_at, last_error, created_at
		FROM tenant.log_sinks WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Sink, 0)
	for rows.Next() {
		var sk Sink
		if err := rows.Scan(&sk.ID, &sk.Type, &sk.Endpoint, &sk.Enabled, &sk.LastForwardedAt, &sk.LastError, &sk.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sk)
	}
	return out, rows.Err()
}

func (s *Service) SetEnabled(ctx context.Context, id, tenantID uuid.UUID, enabled bool) error {
	ct, err := s.pool.Exec(ctx, `UPDATE tenant.log_sinks SET enabled = $3 WHERE id = $1 AND tenant_id = $2`, id, tenantID, enabled)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM tenant.log_sinks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
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
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, type, endpoint, token,
		       COALESCE(cursor_created_at, NOW()), COALESCE(cursor_id, '00000000-0000-0000-0000-000000000000')
		FROM tenant.log_sinks WHERE enabled
	`)
	if err != nil {
		return err
	}
	var sinks []sinkRow
	for rows.Next() {
		var r sinkRow
		if err := rows.Scan(&r.id, &r.tenantID, &r.typ, &r.endpoint, &r.token, &r.cursorAt, &r.cursorID); err != nil {
			rows.Close()
			return err
		}
		sinks = append(sinks, r)
	}
	rows.Close()
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
	_, _ = s.pool.Exec(ctx, `
		UPDATE tenant.log_sinks
		SET cursor_created_at = $2, cursor_id = $3, last_forwarded_at = NOW(), last_error = ''
		WHERE id = $1
	`, sk.id, lastAt, lastID)
}

func (s *Service) fetchEvents(ctx context.Context, tenantID uuid.UUID, afterAt time.Time, afterID uuid.UUID) ([]AuditEvent, time.Time, uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, actor_user_id, actor_type, action, resource_type, resource_id,
		       host(ip), request_id, created_at
		FROM audit.events
		WHERE tenant_id = $1 AND (created_at, id) > ($2, $3)
		ORDER BY created_at ASC, id ASC
		LIMIT $4
	`, tenantID, afterAt, afterID, forwardBatch)
	if err != nil {
		return nil, afterAt, afterID, err
	}
	defer rows.Close()
	var (
		out    []AuditEvent
		lastAt = afterAt
		lastID = afterID
	)
	for rows.Next() {
		var (
			e       AuditEvent
			id      uuid.UUID
			tid     *uuid.UUID
			actorID *uuid.UUID
			resType *string
			resID   *uuid.UUID
		)
		if err := rows.Scan(&id, &tid, &actorID, &e.ActorType, &e.Action, &resType, &resID, &e.IP, &e.RequestID, &e.CreatedAt); err != nil {
			return nil, afterAt, afterID, err
		}
		e.ID = id.String()
		if tid != nil {
			e.TenantID = tid.String()
		}
		if actorID != nil {
			s := actorID.String()
			e.ActorUserID = &s
		}
		if resType != nil {
			e.ResourceType = *resType
		}
		if resID != nil {
			s := resID.String()
			e.ResourceID = &s
		}
		out = append(out, e)
		lastAt, lastID = e.CreatedAt, id
	}
	return out, lastAt, lastID, rows.Err()
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
	_, _ = s.pool.Exec(ctx, `UPDATE tenant.log_sinks SET last_error = $2 WHERE id = $1`, id, msg)
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
