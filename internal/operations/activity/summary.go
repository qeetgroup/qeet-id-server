package activity

import (
	"net/http"
	"strconv"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Summary window and bucket bounds. The window defaults to the last 24h and is
// capped at a year and a day, so the per-organization aggregates never scan
// unbounded history; a long window gets buckets of up to a week.
const (
	summaryDefaultWindow = 24 * time.Hour
	summaryMaxWindow     = 366 * 24 * time.Hour
	summaryDefaultBucket = int64(3600)
	summaryMinBucket     = int64(60)
	summaryMaxBucket     = int64(7 * 86400)
	summaryTargetBuckets = 48
)

// activitySummaryResponse is the aggregate wire shape for GET /v1/activity/summary.
type activitySummaryResponse struct {
	Total          int64            `json:"total"`
	UniqueActors   int64            `json:"unique_actors"`
	Actors         actorCounts      `json:"actors"`
	SecurityAlerts int64            `json:"security_alerts"`
	BySeverity     map[string]int64 `json:"by_severity"`
	ByCategory     map[string]int64 `json:"by_category"`
	ByOutcome      map[string]int64 `json:"by_outcome"`
	Series         []summaryBucket  `json:"series"`
	BucketSeconds  int64            `json:"bucket_seconds"`
	Window         summaryWindow    `json:"window"`
}

// actorCounts is how many distinct actors of each kind the summary's events
// have: people, API keys, agents and service principals.
type actorCounts struct {
	People   int64 `json:"people"`
	APIKeys  int64 `json:"api_keys"`
	Agents   int64 `json:"agents"`
	Services int64 `json:"services"`
}

// summaryBucket is one time slice of the summary series: Count is every event
// in the slice, and the other fields break it down by outcome or severity.
type summaryBucket struct {
	At       time.Time `json:"at"`
	Count    int64     `json:"count"`
	Success  int64     `json:"success"`
	Warning  int64     `json:"warning"`
	Failed   int64     `json:"failed"`
	Info     int64     `json:"info"`
	Critical int64     `json:"critical"`
}

type summaryWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// summary serves GET /v1/activity/summary: counts by severity, category and
// outcome, plus a time series, under the same filters as history. It ignores the
// severity and category filters, because those are what it reports. The query
// groups by action; severityOf and categoryOf fold the groups in Go.
func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	f, err := parseListFilter(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	from, to := summaryWindowOf(f)
	f.From = &from
	f.To = &to
	bucket := summaryBucketOf(r.URL.Query().Get("bucket"), from, to)

	q := dbgen.New(h.pool)
	ctx := r.Context()

	p := historyParams(organizationID, f)
	byAction, err := q.SummarizeActivityByAction(ctx, dbgen.SummarizeActivityByActionParams{
		OrganizationID: p.OrganizationID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, QLike: p.QLike, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	totals, err := q.SummarizeActivityTotals(ctx, dbgen.SummarizeActivityTotalsParams{
		OrganizationID: p.OrganizationID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, QLike: p.QLike, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	series, err := q.SummarizeActivityTimeSeries(ctx, dbgen.SummarizeActivityTimeSeriesParams{
		BucketSeconds:  bucket,
		OrganizationID: p.OrganizationID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, QLike: p.QLike, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// Zero-fill all buckets so the console renders a stable legend.
	bySeverity := map[string]int64{
		SeverityInfo: 0, SeveritySuccess: 0, SeverityWarning: 0, SeverityError: 0, SeverityCritical: 0,
	}
	byCategory := map[string]int64{
		CategoryAuthentication: 0, CategoryAuthorization: 0, CategorySecurity: 0,
		CategoryDirectory: 0, CategoryDeveloper: 0, CategorySystem: 0,
	}
	byOutcome := map[string]int64{"success": 0, "warning": 0, "failed": 0, "info": 0}
	for _, row := range byAction {
		sev := severityOf(row.Action)
		bySeverity[sev] += row.Count
		byCategory[categoryOf(row.Action)] += row.Count
		byOutcome[outcomeOf(sev)] += row.Count
	}

	out := foldSeries(series)

	httpx.WriteJSON(w, http.StatusOK, activitySummaryResponse{
		Total:        totals.Total,
		UniqueActors: totals.UniqueActors,
		Actors: actorCounts{
			People: totals.UniqueActors, APIKeys: totals.UniqueApiKeys,
			Agents: totals.UniqueAgents, Services: totals.UniqueServices,
		},
		SecurityAlerts: bySeverity[SeverityCritical],
		BySeverity:     bySeverity,
		ByCategory:     byCategory,
		ByOutcome:      byOutcome,
		Series:         out,
		BucketSeconds:  bucket,
		Window:         summaryWindow{From: from, To: to},
	})
}

// summaryWindowOf is the summary's window for f: the last 24h unless f says
// otherwise, at most summaryMaxWindow long, and the last 24h again when f's
// from is not before its to.
func summaryWindowOf(f ListFilter) (from, to time.Time) {
	to = time.Now().UTC()
	if f.To != nil {
		to = f.To.UTC()
	}
	from = to.Add(-summaryDefaultWindow)
	if f.From != nil {
		from = f.From.UTC()
	}
	if to.Sub(from) > summaryMaxWindow {
		from = to.Add(-summaryMaxWindow)
	}
	if !from.Before(to) {
		from = to.Add(-summaryDefaultWindow)
	}
	return from, to
}

// summaryBucketOf is the series' bucket width in seconds: raw (the ?bucket=
// parameter) when it is a positive number, else about summaryTargetBuckets
// buckets over the window, clamped to summaryMinBucket..summaryMaxBucket.
func summaryBucketOf(raw string, from, to time.Time) int64 {
	bucket := summaryDefaultBucket
	if raw != "" {
		if b, errB := strconv.ParseInt(raw, 10, 64); errB == nil && b > 0 {
			bucket = b
		}
	} else {
		span := int64(to.Sub(from).Seconds())
		if span > 0 {
			bucket = span / summaryTargetBuckets
		}
	}
	if bucket < summaryMinBucket {
		bucket = summaryMinBucket
	}
	if bucket > summaryMaxBucket {
		bucket = summaryMaxBucket
	}
	return bucket
}

// foldSeries folds the per-(bucket, action) rows into per-outcome buckets.
// Rows arrive ordered by bucket, so rows of one bucket are contiguous.
func foldSeries(series []dbgen.SummarizeActivityTimeSeriesRow) []summaryBucket {
	out := make([]summaryBucket, 0)
	for _, s := range series {
		at := s.Bucket.UTC()
		if len(out) == 0 || !out[len(out)-1].At.Equal(at) {
			out = append(out, summaryBucket{At: at})
		}
		i := len(out) - 1
		sev := severityOf(s.Action)
		out[i].Count += s.Count
		switch outcomeOf(sev) {
		case "success":
			out[i].Success += s.Count
		case "warning":
			out[i].Warning += s.Count
		case "failed":
			out[i].Failed += s.Count
		default:
			out[i].Info += s.Count
		}
		if sev == SeverityCritical {
			out[i].Critical += s.Count
		}
	}
	return out
}
