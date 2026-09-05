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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
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
	egress *egress.Policy
	box    *envelope.Cipher
}

func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{
		pool:   pool,
		q:      dbgen.New(pool),
		client: policy.HTTPClient(10 * time.Second),
		egress: policy,
	}
}

func validType(t string) bool {
	return t == typeSplunkHEC || t == typeDatadog || t == typeHTTP
}

// Create registers a sink. It starts streaming from now (cursor = creation
// time), so enabling a sink never dumps the entire audit history downstream.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, typ, endpoint, token string) (*Sink, error) {
	return s.CreateWithActor(ctx, tenantID, typ, endpoint, token, audit.Actor{Type: "system"})
}

func (s *Service) CreateWithActor(ctx context.Context, tenantID uuid.UUID, typ, endpoint, token string, actor audit.Actor) (*Sink, error) {
	if !validType(typ) {
		return nil, errs.ErrSIEMSinkTypeInvalid
	}
	if _, err := s.egress.ValidateHTTPURL(endpoint); err != nil {
		return nil, errs.ErrSIEMEndpointInvalid
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("SIEM token encryption is unavailable")
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(tenantID, "siem-token", id.String(), []byte(token))
	if err != nil {
		return nil, err
	}
	var row struct {
		ID              uuid.UUID
		Type            string
		Endpoint        string
		Enabled         bool
		LastForwardedAt pgtype.Timestamptz
		LastError       string
		CreatedAt       time.Time
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.log_sinks
		    (id, tenant_id, type, endpoint, token, token_ct, token_nonce,
		     encryption_version, cursor_created_at, cursor_id)
		VALUES ($1, $2, $3, $4, '', $5, $6, 1, NOW(), '00000000-0000-0000-0000-000000000000')
		RETURNING id, type, endpoint, enabled, last_forwarded_at, last_error, created_at
	`, id, tenantID, typ, endpoint, ciphertext, nonce).Scan(
		&row.ID, &row.Type, &row.Endpoint, &row.Enabled, &row.LastForwardedAt, &row.LastError, &row.CreatedAt,
	)
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
	metadata := map[string]any{"type": sk.Type, "endpoint": sk.Endpoint}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "siem.sink_created", "log_sink", sk.ID, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: sk.ID, Topic: "siem.events", EventType: "siem.sink_created",
		Payload: map[string]any{"sink_id": sk.ID, "tenant_id": tenantID, "type": sk.Type, "endpoint": sk.Endpoint},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
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
	return s.SetEnabledWithActor(ctx, id, tenantID, enabled, audit.Actor{Type: "system"})
}

func (s *Service) SetEnabledWithActor(ctx context.Context, id, tenantID uuid.UUID, enabled bool, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).SetLogSinkEnabled(ctx, dbgen.SetLogSinkEnabledParams{
		Enabled: enabled, ID: id, TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	metadata := map[string]any{"enabled": enabled}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "siem.sink_updated", "log_sink", id, metadata)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "siem.events", EventType: "siem.sink_updated", Payload: map[string]any{"sink_id": id, "tenant_id": tenantID, "enabled": enabled}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	n, err := s.q.WithTx(tx).DeleteLogSink(ctx, dbgen.DeleteLogSinkParams{
		ID: id, TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "siem.sink_deleted", "log_sink", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "siem.events", EventType: "siem.sink_deleted", Payload: map[string]any{"sink_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Run is the background forwarder. It is a no-op when no sinks are enabled.
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
	id, tenantID  uuid.UUID
	typ, endpoint string
	token         string
	cursorAt      time.Time
	cursorID      uuid.UUID
}

type storedSink struct {
	id, tenantID        uuid.UUID
	typ, endpoint       string
	legacyToken         string
	tokenCT, tokenNonce []byte
	cursorAt            pgtype.Timestamptz
	cursorID            pgtype.UUID
}

func (s *Service) forwardDue(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, type, endpoint, token, token_ct, token_nonce,
		       cursor_created_at, cursor_id
		FROM tenant.log_sinks
		WHERE enabled
	`)
	if err != nil {
		return err
	}
	var stored []storedSink
	for rows.Next() {
		var r storedSink
		if err := rows.Scan(&r.id, &r.tenantID, &r.typ, &r.endpoint, &r.legacyToken,
			&r.tokenCT, &r.tokenNonce, &r.cursorAt, &r.cursorID); err != nil {
			rows.Close()
			return err
		}
		stored = append(stored, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	sinks := make([]sinkRow, 0, len(stored))
	for _, r := range stored {
		tokenValue := r.legacyToken
		if len(r.tokenCT) > 0 {
			if s.box == nil {
				return errors.New("SIEM token encryption is unavailable")
			}
			plain, openErr := s.box.Open(r.tenantID, "siem-token", r.id.String(), r.tokenCT, r.tokenNonce)
			if openErr != nil {
				return openErr
			}
			tokenValue = string(plain)
		} else if tokenValue != "" && s.box != nil {
			ct, nonce, sealErr := s.box.Seal(r.tenantID, "siem-token", r.id.String(), []byte(tokenValue))
			if sealErr != nil {
				return sealErr
			}
			if _, updateErr := s.pool.Exec(ctx, `
				UPDATE tenant.log_sinks
				SET token = '', token_ct = $2, token_nonce = $3, encryption_version = 1
				WHERE id = $1 AND token_ct IS NULL
			`, r.id, ct, nonce); updateErr != nil {
				return updateErr
			}
		}
		sk := sinkRow{
			id: r.id, tenantID: r.tenantID,
			typ: r.typ, endpoint: r.endpoint, token: tokenValue,
			// Apply COALESCE defaults in Go: null cursor_created_at → NOW(),
			// null cursor_id → zero UUID (matches the INSERT default).
			cursorAt: time.Now(),
			cursorID: uuid.UUID{},
		}
		if r.cursorAt.Valid {
			sk.cursorAt = r.cursorAt.Time
		}
		if r.cursorID.Valid {
			sk.cursorID = uuid.UUID(r.cursorID.Bytes)
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

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/log-sinks", h.list)
	r.Post("/tenants/{tenantID}/log-sinks", h.create)
	r.Patch("/tenants/{tenantID}/log-sinks/{id}", h.patch)
	r.Delete("/tenants/{tenantID}/log-sinks/{id}", h.del)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrSIEMTenantInvalid
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrSIEMTenantMismatch
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
	sk, err := h.Service.CreateWithActor(r.Context(), tenantID, in.Type, in.Endpoint, in.Token, actorOf(r))
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
		httpx.WriteError(w, r, errs.ErrSIEMIDInvalid)
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.SetEnabledWithActor(r.Context(), id, tenantID, in.Enabled, actorOf(r)); err != nil {
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
		httpx.WriteError(w, r, errs.ErrSIEMIDInvalid)
		return
	}
	if err := h.Service.DeleteWithActor(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
