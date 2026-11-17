// Package decisionlog keeps the access decisions an organization asks of the
// platform (the check, relationship check, AuthZEN and ABAC evaluate calls)
// for 30 days, and lists them. Decisions are queued and written in batches in
// the background, so a check never waits on its record; when the queue is
// full a record is dropped, and counted in the log, rather than slow the check.
package decisionlog

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Sources: the calls whose decisions are kept.
const (
	SourceCheck         = "check"
	SourceRelationCheck = "relation_check"
	SourceAuthZEN       = "authzen"
	SourceABACEvaluate  = "abac_evaluate"
	SourceABACDraft     = "abac_draft" // an evaluation with an unsaved policy
)

const (
	queueSize  = 10000           // decisions waiting to be written
	batchSize  = 500             // decisions written at once
	flushEvery = time.Second     // how long a decision may wait for a batch
	maxWait    = 2 * time.Second // how long the last batch may take at shutdown
)

// Entry is one decision to keep: in OrganizationID, about Subject (a user id, or a
// type:id subject) doing Action on Resource, its answer, and the model, rule
// and reason that decided it.
type Entry struct {
	OrganizationID uuid.UUID
	Source         string
	Subject        string
	Resource       string
	Action         string
	Allowed        bool
	Model          string
	Rule           string
	ReasonCode     string
}

type record struct {
	Entry
	at                       time.Time
	callerType, callerClient string
	callerID                 *uuid.UUID
}

// Log keeps decisions. A nil Log keeps none.
type Log struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	queue   chan record
	dropped atomic.Int64
}

// New returns a Log writing to pool once Run runs.
func New(pool *pgxpool.Pool) *Log {
	return &Log{pool: pool, q: dbgen.New(pool), queue: make(chan record, queueSize)}
}

// Record queues e, asked by ctx's caller, without waiting.
func (l *Log) Record(ctx context.Context, e Entry) {
	if l == nil || e.OrganizationID == uuid.Nil {
		return
	}
	r := record{Entry: e, at: time.Now().UTC()}
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		r.callerType, r.callerClient = p.ActorType, p.ClientID
		switch {
		case p.UserID != nil:
			r.callerID = p.UserID
		case p.AgentID != nil:
			r.callerID = p.AgentID
		default:
			if id, err := uuid.Parse(p.Subject); err == nil {
				r.callerID = &id
			}
		}
		if r.callerType == "" && p.UserID != nil {
			r.callerType = "user"
		}
	}
	select {
	case l.queue <- r:
	default:
		if n := l.dropped.Add(1); n%1000 == 1 {
			slog.Warn("decision log full: decisions dropped", "dropped", n)
		}
	}
}

// Run writes queued decisions in batches until ctx ends, then writes what is
// left.
func (l *Log) Run(ctx context.Context) {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	batch := make([]record, 0, batchSize)
	for {
		select {
		case r := <-l.queue:
			if batch = append(batch, r); len(batch) >= batchSize {
				batch = l.write(ctx, batch)
			}
		case <-ticker.C:
			batch = l.write(ctx, batch)
		case <-ctx.Done():
			for len(l.queue) > 0 {
				batch = append(batch, <-l.queue)
			}
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), maxWait)
			l.write(final, batch)
			cancel()
			return
		}
	}
}

// insertDecisions writes a batch of decisions given column by column. COPY
// isn't allowed on a table with row-level security, so it is an INSERT.
const insertDecisions = `INSERT INTO auth.authz_decisions
	(organization_id, decided_at, source, caller_type, caller_id, caller_client, subject, resource, action, allowed, model, rule, reason_code)
SELECT * FROM unnest($1::uuid[], $2::timestamptz[], $3::text[], $4::text[], $5::uuid[], $6::text[], $7::text[],
	$8::text[], $9::text[], $10::boolean[], $11::text[], $12::text[], $13::text[])`

// write writes batch and returns it emptied.
func (l *Log) write(ctx context.Context, batch []record) []record {
	if len(batch) == 0 {
		return batch
	}
	n := len(batch)
	organizations, callers := make([]uuid.UUID, n), make([]pgtype.UUID, n)
	at, allowed := make([]time.Time, n), make([]bool, n)
	text := make([][]string, 9)
	for i := range text {
		text[i] = make([]string, n)
	}
	for i, r := range batch {
		organizations[i], at[i], allowed[i] = r.OrganizationID, r.at, r.Allowed
		if r.callerID != nil {
			callers[i] = pgtype.UUID{Bytes: *r.callerID, Valid: true}
		}
		for c, v := range []string{r.Source, r.callerType, r.callerClient, r.Subject, r.Resource, r.Action, r.Model, r.Rule, r.ReasonCode} {
			text[c][i] = v
		}
	}
	if _, err := l.pool.Exec(ctx, insertDecisions, organizations, at, text[0], text[1], callers, text[2],
		text[3], text[4], text[5], allowed, text[6], text[7], text[8]); err != nil {
		slog.Warn("decision log: decisions not written", "count", n, "err", err)
	}
	return batch[:0]
}

// Decision is a kept decision.
type Decision struct {
	ID           uuid.UUID  `json:"id"`
	DecidedAt    time.Time  `json:"decided_at"`
	Source       string     `json:"source"`
	CallerType   string     `json:"caller_type,omitempty"`
	CallerID     *uuid.UUID `json:"caller_id,omitempty"`
	CallerClient string     `json:"caller_client,omitempty"`
	Subject      string     `json:"subject"`
	Resource     string     `json:"resource"`
	Action       string     `json:"action"`
	Allowed      bool       `json:"allowed"`
	Model        string     `json:"model"`
	Rule         string     `json:"rule,omitempty"`
	ReasonCode   string     `json:"reason_code,omitempty"`
}

// Page is a page of decisions; NextCursor fetches the next, "" on the last.
type Page struct {
	Items      []Decision `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// Filter narrows a list: to a subject, a source and an answer when set, and
// to decisions of the last Days days (1..30, default 30).
type Filter struct {
	Subject, Source string
	Allowed         *bool
	Days, Limit     int
	Cursor          string
}

// List returns a page of up to f.Limit (1..200, default 50) of the organization's
// decisions, newest first.
func (l *Log) List(ctx context.Context, organizationID uuid.UUID, f Filter) (*Page, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Days <= 0 || f.Days > 30 {
		f.Days = 30
	}
	before, beforeID := time.Now().Add(time.Hour), uuid.Max
	if f.Cursor != "" {
		var err error
		if before, beforeID, err = paging.DecodeTimeUUID(f.Cursor); err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
	}
	params := dbgen.ListDecisionsParams{OrganizationID: organizationID, Allowed: f.Allowed, Since: time.Now().AddDate(0, 0, -f.Days),
		BeforeTs: before, BeforeID: beforeID, RowLimit: int32(f.Limit + 1)} // #nosec G115 -- limit is at most 200
	if f.Subject != "" {
		params.Subject = &f.Subject
	}
	if f.Source != "" {
		params.Source = &f.Source
	}
	rows, err := l.q.ListDecisions(ctx, params)
	if err != nil {
		return nil, err
	}
	page := &Page{Items: make([]Decision, 0, len(rows))}
	for _, r := range rows {
		d := Decision{ID: r.ID, DecidedAt: r.DecidedAt, Source: r.Source, CallerType: r.CallerType, CallerClient: r.CallerClient,
			Subject: r.Subject, Resource: r.Resource, Action: r.Action, Allowed: r.Allowed, Model: r.Model, Rule: r.Rule, ReasonCode: r.ReasonCode}
		if r.CallerID.Valid {
			id := uuid.UUID(r.CallerID.Bytes)
			d.CallerID = &id
		}
		page.Items = append(page.Items, d)
	}
	if len(page.Items) > f.Limit {
		page.Items = page.Items[:f.Limit]
		last := page.Items[f.Limit-1]
		page.NextCursor = paging.EncodeTimeUUID(last.DecidedAt, last.ID)
	}
	return page, nil
}

// Handler serves the decision log.
type Handler struct {
	Log *Log
}

// Mount registers GET /tenants/{tenantID}/authorization/decisions.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/authorization/decisions", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	f := Filter{Subject: q.Get("subject"), Source: q.Get("source"), Cursor: q.Get("cursor")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Days, _ = strconv.Atoi(q.Get("days"))
	if a := q.Get("allowed"); a != "" {
		allowed, err := strconv.ParseBool(a)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid allowed"))
			return
		}
		f.Allowed = &allowed
	}
	out, err := h.Log.List(r.Context(), organizationID, f)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
