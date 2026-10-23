// Package siem streams a tenant's audit events to an external collector: Splunk
// HEC, Datadog logs or a generic HTTP endpoint. A sink streams from when it was
// created, with no backfill, and delivery is at-least-once: its cursor advances
// only after a 2xx.
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

// Sink is a tenant's configured log destination. Its token is stored encrypted
// and never returned.
type Sink struct {
	ID              uuid.UUID  `json:"id"`
	Type            string     `json:"type"`
	Endpoint        string     `json:"endpoint"`
	Enabled         bool       `json:"enabled"`
	LastForwardedAt *time.Time `json:"last_forwarded_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// AuditEvent is the forwarded form of an audit row.
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

// Service manages tenants' log sinks and forwards audit events to them. Sink
// tokens are sealed with the cipher from SetCipher; without one, no sink can be
// created.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	client *http.Client
	egress *egress.Policy
	box    *envelope.Cipher
}

// SetCipher sets the cipher that encrypts sink tokens.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// NewService returns a Service whose HTTP client follows policies[0], or by
// default may reach only public https endpoints.
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

// Create registers a sink with its token encrypted, recording it in
// the audit log and the outbox. The sink streams from now, so it never receives
// the existing audit history.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, typ, endpoint, token string, actor audit.Actor) (*Sink, error) {
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

// List returns the tenant's sinks.
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

// SetEnabled enables or disables one of the tenant's sinks. It returns
// errs.ErrNotFound if there is no such sink.
func (s *Service) SetEnabled(ctx context.Context, id, tenantID uuid.UUID, enabled bool, actor audit.Actor) error {
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

// Delete deletes one of the tenant's sinks. It returns
// errs.ErrNotFound if there is no such sink.
func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
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

// forwardDue forwards new events to every enabled sink, first encrypting any
// token still stored in plaintext.
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
			// A NULL cursor means "from now", with the zero UUID, as the INSERT
			// default does.
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
	// Advance the cursor; on error, the next tick resends the batch.
	_ = s.q.AdvanceLogSinkCursor(ctx, dbgen.AdvanceLogSinkCursorParams{
		CursorCreatedAt: pgtype.Timestamptz{Time: lastAt, Valid: true},
		CursorID:        pgtype.UUID{Bytes: lastID, Valid: true},
		ID:              sk.id,
	})
}

func (s *Service) fetchEvents(ctx context.Context, tenantID uuid.UUID, afterAt time.Time, afterID uuid.UUID) ([]AuditEvent, time.Time, uuid.UUID, error) {
	// audit.events.tenant_id is nullable, so it takes a pgtype.UUID.
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
		// The query maps a NULL ip to ""; turn that back into nil.
		if r.Host != "" {
			h := r.Host
			e.IP = &h
		}
		// request_id is nullable; nil means none was recorded.
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

// Handler serves the log-sink endpoints.
type Handler struct {
	Service *Service
}

// Mount registers the log-sink routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/log-sinks", h.list)
	r.Post("/tenants/{tenantID}/log-sinks", h.create)
	r.Patch("/tenants/{tenantID}/log-sinks/{id}", h.patch)
	r.Delete("/tenants/{tenantID}/log-sinks/{id}", h.del)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrSIEMTenantInvalid, errs.ErrSIEMTenantMismatch)
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
	sk, err := h.Service.Create(r.Context(), tenantID, in.Type, in.Endpoint, in.Token, audit.ActorOf(r))
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
	if err := h.Service.SetEnabled(r.Context(), id, tenantID, in.Enabled, audit.ActorOf(r)); err != nil {
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
	if err := h.Service.Delete(r.Context(), id, tenantID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
