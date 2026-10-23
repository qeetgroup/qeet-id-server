package outbox

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// LagCollector reports the outbox's backlog, read at scrape time: how many
// events await publishing and how long the oldest has waited. A growing age
// means events are not reaching their subscribers.
func LagCollector(pool *pgxpool.Pool) prometheus.Collector {
	return &lag{
		pool:    pool,
		pending: prometheus.NewDesc("outbox_unpublished_events", "Outbox events not yet published.", nil, nil),
		oldest:  prometheus.NewDesc("outbox_oldest_unpublished_age_seconds", "How long the oldest unpublished outbox event has waited, or 0.", nil, nil),
	}
}

type lag struct {
	pool            *pgxpool.Pool
	pending, oldest *prometheus.Desc
}

func (c *lag) Describe(ch chan<- *prometheus.Desc) { ch <- c.pending; ch <- c.oldest }

func (c *lag) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n int64
	var age float64
	if err := c.pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at)), 0)::float8
		FROM platform.outbox WHERE published_at IS NULL
	`).Scan(&n, &age); err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(n))
	ch <- prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, age)
}
