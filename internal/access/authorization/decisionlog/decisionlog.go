// Package decisionlog keeps for 30 days, and lists, the access decisions an organization asks of the
// platform (check, relationship check, AuthZEN and ABAC evaluate). Records are queued and written in
// background batches so a check never waits; a full queue drops a record, counting it, rather than
// slow the check.
package decisionlog

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog/dbgen"
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

// write writes batch and returns it emptied.
func (l *Log) write(ctx context.Context, batch []record) []record {
	if len(batch) == 0 {
		return batch
	}
	n := len(batch)
	p := dbgen.InsertDecisionsParams{
		OrganizationIds: make([]uuid.UUID, n), DecidedAt: make([]time.Time, n), Allowed: make([]bool, n),
		Sources: make([]string, n), CallerTypes: make([]string, n), CallerIds: make([]string, n),
		CallerClients: make([]string, n), Subjects: make([]string, n), Resources: make([]string, n),
		Actions: make([]string, n), Models: make([]string, n), Rules: make([]string, n), ReasonCodes: make([]string, n),
	}
	for i, r := range batch {
		p.OrganizationIds[i], p.DecidedAt[i], p.Allowed[i] = r.OrganizationID, r.at, r.Allowed
		p.Sources[i], p.CallerTypes[i], p.CallerClients[i] = r.Source, r.callerType, r.callerClient
		p.Subjects[i], p.Resources[i], p.Actions[i] = r.Subject, r.Resource, r.Action
		p.Models[i], p.Rules[i], p.ReasonCodes[i] = r.Model, r.Rule, r.ReasonCode
		if r.callerID != nil {
			p.CallerIds[i] = r.callerID.String()
		}
	}
	if err := l.q.InsertDecisions(ctx, p); err != nil {
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

// Filter narrows a list: to a subject, a source and an answer when set, and
// to decisions of the last Days days (1..30, default 30). After is where the
// page starts, and Limit its size (50 when unset, at most 200).
type Filter struct {
	Subject, Source string
	Allowed         *bool
	Days, Limit     int
	After           paging.Cursor
}

// List returns a page of the organization's decisions, newest first.
func (l *Log) List(ctx context.Context, organizationID uuid.UUID, f Filter) (paging.Result[Decision], error) {
	f.Limit = paging.Clamp(f.Limit, 50, 200)
	if f.Days <= 0 || f.Days > 30 {
		f.Days = 30
	}
	params := dbgen.ListDecisionsParams{OrganizationID: organizationID, Allowed: f.Allowed, Since: time.Now().AddDate(0, 0, -f.Days),
		RowLimit: int32(f.Limit + 1)} // #nosec G115 -- limit is at most 200
	params.BeforeTs, params.BeforeID = f.After.Before()
	if f.Subject != "" {
		params.Subject = &f.Subject
	}
	if f.Source != "" {
		params.Source = &f.Source
	}
	rows, err := l.q.ListDecisions(ctx, params)
	if err != nil {
		return paging.Result[Decision]{}, err
	}
	items := make([]Decision, len(rows))
	for i, r := range rows {
		items[i] = Decision{ID: r.ID, DecidedAt: r.DecidedAt, Source: r.Source, CallerType: r.CallerType, CallerClient: r.CallerClient,
			Subject: r.Subject, Resource: r.Resource, Action: r.Action, Allowed: r.Allowed, Model: r.Model, Rule: r.Rule, ReasonCode: r.ReasonCode, CallerID: r.CallerID}
	}
	return paging.Page(paging.Next(items, f.Limit, func(d Decision) (time.Time, uuid.UUID) { return d.DecidedAt, d.ID })), nil
}
