package webhook

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook/dbgen"
)

// deliveries counts delivery attempts by outcome: delivered, retry (scheduled again with backoff) or
// dead (given up: out of attempts, or refused by the endpoint).
var deliveries = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "webhook_deliveries_total",
	Help: "Webhook delivery attempts by outcome: delivered, retry or dead.",
}, []string{"outcome"})

// BacklogCollector reports, at scrape time, the deliveries still to be made across every
// organization and how long the oldest has waited: a growing age means endpoints aren't receiving
// their events. A failed read reports nothing.
func BacklogCollector(pool *pgxpool.Pool) prometheus.Collector {
	return &backlog{
		q:       dbgen.New(pool),
		pending: prometheus.NewDesc("webhook_pending_deliveries", "Webhook deliveries not yet made.", nil, nil),
		oldest:  prometheus.NewDesc("webhook_oldest_pending_age_seconds", "How long the oldest pending webhook delivery has waited, or 0.", nil, nil),
	}
}

type backlog struct {
	q               *dbgen.Queries
	pending, oldest *prometheus.Desc
}

func (c *backlog) Describe(ch chan<- *prometheus.Desc) { ch <- c.pending; ch <- c.oldest }

func (c *backlog) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	row, err := c.q.PendingDeliveriesSummary(ctx)
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(row.Pending))
	ch <- prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, row.OldestAgeSeconds)
}
