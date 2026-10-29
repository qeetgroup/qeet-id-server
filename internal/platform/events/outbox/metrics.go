package outbox

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// LagCollector reports the outbox's backlog, read at scrape time: how many
// events await publishing, how long the oldest has waited, and how many are
// dead-lettered. A growing age means events are not reaching their
// subscribers; a dead letter is an event they never got.
func LagCollector(pool *pgxpool.Pool) prometheus.Collector {
	return &lag{
		pool:    pool,
		pending: prometheus.NewDesc("outbox_unpublished_events", "Outbox events not yet published.", nil, nil),
		oldest:  prometheus.NewDesc("outbox_oldest_unpublished_age_seconds", "How long the oldest unpublished outbox event has waited, or 0.", nil, nil),
		dead:    prometheus.NewDesc("outbox_dead_letters", "Outbox events in the dead-letter table, never published.", nil, nil),
	}
}

type lag struct {
	pool                  *pgxpool.Pool
	pending, oldest, dead *prometheus.Desc
}

func (c *lag) Describe(ch chan<- *prometheus.Desc) { ch <- c.pending; ch <- c.oldest; ch <- c.dead }

func (c *lag) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n, dead int64
	var age float64
	if err := c.pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at)), 0)::float8,
		       (SELECT count(*) FROM platform.outbox_dead_letter)
		FROM platform.outbox WHERE published_at IS NULL
	`).Scan(&n, &age, &dead); err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(n))
	ch <- prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, age)
	ch <- prometheus.MustNewConstMetric(c.dead, prometheus.GaugeValue, float64(dead))
}
