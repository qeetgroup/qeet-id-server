// Package anomaly scores audit events against a baseline per (organization, actor)
// and flags deviations (first-time action, unusual hour, new IP) for review. A
// background sweep scores events in batches, so audit.Record stays fast and
// does not depend on this package.
package anomaly

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly/dbgen"
)

const (
	sweepInterval = time.Minute
	sweepBatch    = 200
	sweepBudget   = 45 * time.Second // one sweep's batches, so it ends before the next is due

	defaultScoreThreshold    = 0.6
	defaultMinBaselineEvents = 20

	// Scoring weights. A new action is the strongest signal and a new IP the
	// weakest: admins change networks far more often than what they do.
	weightAction = 0.5
	weightHour   = 0.3
	weightIP     = 0.2
)

// Anomaly is a flagged deviation, enriched with the underlying event's
// details for display.
type Anomaly struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	EventID        uuid.UUID  `json:"event_id"`
	ActorUserID    *uuid.UUID `json:"actor_user_id"`
	ActorEmail     *string    `json:"actor_email"`
	Score          float64    `json:"score"`
	Reasons        []string   `json:"reasons"`
	Status         string     `json:"status"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	ResolvedBy     *uuid.UUID `json:"resolved_by"`
	CreatedAt      time.Time  `json:"created_at"`
	Action         string     `json:"action"`
	ResourceType   string     `json:"resource_type"`
	IP             *string    `json:"ip"`
	EventAt        time.Time  `json:"event_at"`
}

// Settings is an organization's anomaly-scoring configuration. Events score only once
// the actor has MinBaselineEvents of history, and are flagged at or above
// ScoreThreshold.
type Settings struct {
	OrganizationID    uuid.UUID `json:"organization_id"`
	Enabled           bool      `json:"enabled"`
	ScoreThreshold    float64   `json:"score_threshold"`
	MinBaselineEvents int       `json:"min_baseline_events"`
}

// Summary counts an organization's anomalies.
type Summary struct {
	Open       int `json:"open"`            // open anomalies
	Resolved7d int `json:"resolved_7d"`     // anomalies resolved in the last 7 days
	HighScore  int `json:"high_score_open"` // open anomalies scoring at least 0.85
}

// Service scores audit events and manages the anomalies it flags.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns a Service over pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// baseline is the counter state for one (organization, actor) pair.
type baseline struct {
	eventCount int64
	actions    map[string]int64
	hours      map[string]int64
	ips        map[string]int64
}

func emptyBaseline() baseline {
	return baseline{actions: map[string]int64{}, hours: map[string]int64{}, ips: map[string]int64{}}
}

func (s *Service) loadBaseline(ctx context.Context, tx pgx.Tx, organizationID, actorID uuid.UUID) (baseline, error) {
	b := emptyBaseline()
	row, err := s.q.WithTx(tx).GetActorBaseline(ctx, dbgen.GetActorBaselineParams{
		OrganizationID: organizationID,
		ActorUserID:    actorID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	b.eventCount = row.EventCount
	_ = json.Unmarshal(row.Actions, &b.actions)
	_ = json.Unmarshal(row.Hours, &b.hours)
	_ = json.Unmarshal(row.Ips, &b.ips)
	return b, nil
}

func (s *Service) saveBaseline(ctx context.Context, tx pgx.Tx, organizationID, actorID uuid.UUID, b baseline) error {
	actionsJSON, _ := json.Marshal(b.actions)
	hoursJSON, _ := json.Marshal(b.hours)
	ipsJSON, _ := json.Marshal(b.ips)
	return s.q.WithTx(tx).UpsertActorBaseline(ctx, dbgen.UpsertActorBaselineParams{
		OrganizationID: organizationID,
		ActorUserID:    actorID,
		EventCount:     b.eventCount,
		Actions:        actionsJSON,
		Hours:          hoursJSON,
		Ips:            ipsJSON,
	})
}

// score compares an event with the actor's baseline from before it and returns
// a 0..1 anomaly score and the reasons for it. Each signal is a simple novelty
// measure, so every score can be explained.
func score(b baseline, action, ip string, hour int) (float64, []string) {
	var total float64
	var reasons []string

	if b.actions[action] == 0 {
		total += weightAction
		reasons = append(reasons, "new_action_type")
	}

	hourKey := hourBucket(hour)
	hourFreq := 0.0
	if b.eventCount > 0 {
		hourFreq = float64(b.hours[hourKey]) / float64(b.eventCount)
	}
	// A never-seen hour scores the full weight; an hour holding at least 1/8 of
	// the actor's events scores nothing.
	hourNovelty := 1 - hourFreq*8
	if hourNovelty < 0 {
		hourNovelty = 0
	}
	if hourNovelty > 0 {
		total += weightHour * hourNovelty
	}
	if hourNovelty >= 0.5 {
		reasons = append(reasons, "unusual_hour")
	}

	if ip != "" && b.ips[ip] == 0 {
		total += weightIP
		reasons = append(reasons, "new_ip")
	}

	if total > 1 {
		total = 1
	}
	return total, reasons
}

func hourBucket(hour int) string { return strconv.Itoa(hour) }

func fold(b baseline, action, ip string, hour int) baseline {
	b.eventCount++
	b.actions[action]++
	b.hours[hourBucket(hour)]++
	if ip != "" {
		b.ips[ip]++
	}
	return b
}

// unscoredEvent is the minimal projection of audit.events the scorer needs.
type unscoredEvent struct {
	ID             uuid.UUID
	OrganizationID *uuid.UUID
	ActorUserID    *uuid.UUID
	Action         string
	IP             *string
	CreatedAt      time.Time
}

// settingsFor returns the organization's settings, or the defaults if none are saved,
// read through q.
func settingsFor(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID) (Settings, error) {
	st := Settings{OrganizationID: organizationID, Enabled: true, ScoreThreshold: defaultScoreThreshold, MinBaselineEvents: defaultMinBaselineEvents}
	row, err := q.GetAnomalySettings(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Enabled = row.Enabled
	st.ScoreThreshold = row.ScoreThreshold
	st.MinBaselineEvents = int(row.MinBaselineEvents)
	return st, nil
}

// tick scores unscored events in batches while they come full, within sweepBudget, so the scorer
// keeps up with a busy log. It stops early when a batch scores nothing, as when another instance
// holds every event in it.
func (s *Service) tick(ctx context.Context) error {
	deadline := time.Now().Add(sweepBudget)
	for {
		n, scored, err := s.scoreBatch(ctx)
		if err != nil || n < sweepBatch || scored == 0 || time.Now().After(deadline) {
			return err
		}
	}
}

// scoreBatch scores one batch of unscored events, and returns how many it
// read and how many it scored.
func (s *Service) scoreBatch(ctx context.Context) (int, int, error) {
	rows, err := s.q.ListUnscoredAuditEvents(ctx, int32(sweepBatch))
	if err != nil {
		return 0, 0, err
	}

	// ip is COALESCE(host(ip), ''), typed interface{}; empty becomes nil.
	var batch []unscoredEvent
	for _, r := range rows {
		e := unscoredEvent{
			ID:             r.ID,
			OrganizationID: r.OrganizationID,
			ActorUserID:    r.ActorUserID,
			Action:         r.Action,
			CreatedAt:      r.CreatedAt,
		}
		if ip, ok := r.Ip.(string); ok && ip != "" {
			e.IP = &ip
		}
		batch = append(batch, e)
	}

	scored := 0
	for _, e := range batch {
		done, err := s.scoreOne(ctx, e)
		if err != nil {
			slog.Warn("audit anomaly scoring failed", "event", e.ID, "err", err)
		}
		if done {
			scored++
		}
	}
	return len(rows), scored, nil
}

// scoreOne scores e and folds it into its actor's baseline, reporting whether
// it did. An event another instance is scoring is skipped, not waited for.
func (s *Service) scoreOne(ctx context.Context, e unscoredEvent) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	qTx := s.q.WithTx(tx)
	alreadyScored, err := qTx.LockAuditEventForScoring(ctx, e.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if alreadyScored {
		return false, nil
	}

	// No user actor (agent, service or system): nothing to baseline, so just
	// mark it scored.
	if e.OrganizationID == nil || e.ActorUserID == nil {
		if err := qTx.MarkAuditEventScored(ctx, e.ID); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	settings, err := settingsFor(ctx, qTx, *e.OrganizationID)
	if err != nil {
		return false, err
	}

	ip := ""
	if e.IP != nil {
		if addr, perr := netip.ParseAddr(*e.IP); perr == nil {
			ip = addr.String()
		}
	}
	hour := e.CreatedAt.UTC().Hour()

	if settings.Enabled {
		b, err := s.loadBaseline(ctx, tx, *e.OrganizationID, *e.ActorUserID)
		if err != nil {
			return false, err
		}
		if b.eventCount >= int64(settings.MinBaselineEvents) {
			sc, reasons := score(b, e.Action, ip, hour)
			if sc >= settings.ScoreThreshold {
				if err := qTx.InsertAnomaly(ctx, dbgen.InsertAnomalyParams{
					OrganizationID: *e.OrganizationID,
					EventID:        e.ID,
					ActorUserID:    e.ActorUserID,
					Score:          sc,
					Reasons:        reasons,
				}); err != nil {
					return false, err
				}
			}
		}
		b = fold(b, e.Action, ip, hour)
		if err := s.saveBaseline(ctx, tx, *e.OrganizationID, *e.ActorUserID, b); err != nil {
			return false, err
		}
	}

	if err := qTx.MarkAuditEventScored(ctx, e.ID); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// Run is the background sweeper: it scores a batch every minute until ctx is
// done.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(sweepInterval)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			if err := s.tick(ctx); err != nil {
				slog.Warn("audit anomaly sweep", "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// rowToAnomaly builds an Anomaly from a ListAnomalies row.
func rowToAnomaly(r dbgen.ListAnomaliesRow) Anomaly {
	// ip is COALESCE(host(e.ip), ''), typed interface{}; empty becomes nil.
	var ipPtr *string
	if ip, ok := r.Ip.(string); ok && ip != "" {
		ipPtr = &ip
	}
	return Anomaly{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		EventID:        r.EventID,
		ActorUserID:    r.ActorUserID,
		ActorEmail:     r.Email,
		Score:          r.Score,
		Reasons:        r.Reasons,
		Status:         r.Status,
		ResolvedAt:     r.ResolvedAt,
		ResolvedBy:     r.ResolvedBy,
		CreatedAt:      r.CreatedAt,
		Action:         r.Action,
		ResourceType:   r.ResourceType,
		IP:             ipPtr,
		EventAt:        r.EventAt,
	}
}

// List returns up to limit of the organization's anomalies (50 if limit is not in
// 1..200), newest first. status is "open" or "resolved"; empty returns both.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, status string, limit int) ([]Anomaly, error) {
	out, _, err := s.ListPage(ctx, organizationID, status, limit, paging.Cursor{})
	return out, err
}

// ListPage is List from after the cursor, when one is set, with the next
// page's cursor: empty on the last page.
func (s *Service) ListPage(ctx context.Context, organizationID uuid.UUID, status string, limit int, after paging.Cursor) ([]Anomaly, string, error) {
	limit = paging.Clamp(limit, 50, 200)
	params := dbgen.ListAnomaliesParams{
		OrganizationID: organizationID,
		Status:         strutil.NilIfEmpty(status),
		RowLimit:       int32(limit + 1), // #nosec G115 -- at most 201
	}
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListAnomalies(ctx, params)
	if err != nil {
		return nil, "", err
	}
	out := make([]Anomaly, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToAnomaly(r))
	}
	out, next := paging.Next(out, limit, func(a Anomaly) (time.Time, uuid.UUID) { return a.CreatedAt, a.ID })
	return out, next, nil
}

// Summary returns the organization's anomaly counts.
func (s *Service) Summary(ctx context.Context, organizationID uuid.UUID) (*Summary, error) {
	row, err := s.q.GetAnomalySummary(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	return &Summary{
		Open:       int(row.OpenCount),
		Resolved7d: int(row.Resolved7d),
		HighScore:  int(row.HighScore),
	}, nil
}

// Resolve marks one of the organization's open anomalies resolved by resolvedBy. It
// returns errs.ErrNotFound if there is no such open anomaly.
func (s *Service) Resolve(ctx context.Context, organizationID, id, resolvedBy uuid.UUID) error {
	ct, err := s.q.ResolveAnomaly(ctx, dbgen.ResolveAnomalyParams{
		ResolvedBy:     &resolvedBy,
		ID:             id,
		OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if ct == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// GetSettings returns the organization's settings, or the defaults if none are saved.
func (s *Service) GetSettings(ctx context.Context, organizationID uuid.UUID) (*Settings, error) {
	st, err := settingsFor(ctx, s.q, organizationID)
	return &st, err
}

// UpdateSettings validates and saves the organization's settings.
func (s *Service) UpdateSettings(ctx context.Context, organizationID uuid.UUID, in Settings) (*Settings, error) {
	if in.ScoreThreshold < 0 || in.ScoreThreshold > 1 {
		return nil, ErrAuditScoreThresholdInvalid
	}
	if in.MinBaselineEvents < 0 {
		return nil, ErrAuditMinBaselineInvalid
	}
	if err := s.q.UpsertAnomalySettings(ctx, dbgen.UpsertAnomalySettingsParams{
		OrganizationID:    organizationID,
		Enabled:           in.Enabled,
		ScoreThreshold:    in.ScoreThreshold,
		MinBaselineEvents: int32(in.MinBaselineEvents), // #nosec G115 -- organization's own threshold; truncation grants nothing
	}); err != nil {
		return nil, err
	}
	out := in
	out.OrganizationID = organizationID
	return &out, nil
}
