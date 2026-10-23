package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// PoolCollector reports the connection pool's state at scrape time. Acquired
// connections at the maximum, with acquires waiting, mean requests queue for
// the database.
func PoolCollector(pool *pgxpool.Pool) prometheus.Collector {
	return &poolStats{
		pool:     pool,
		conns:    prometheus.NewDesc("db_pool_connections", "Pool connections by state.", []string{"state"}, nil),
		max:      prometheus.NewDesc("db_pool_max_connections", "The pool's connection limit.", nil, nil),
		acquires: prometheus.NewDesc("db_pool_acquires_total", "Connections acquired from the pool.", nil, nil),
		waited:   prometheus.NewDesc("db_pool_acquires_waited_total", "Acquires that had to wait for a connection.", nil, nil),
		canceled: prometheus.NewDesc("db_pool_acquires_canceled_total", "Acquires given up before a connection was free.", nil, nil),
		waiting:  prometheus.NewDesc("db_pool_acquire_seconds_total", "Total time spent acquiring connections.", nil, nil),
	}
}

type poolStats struct {
	pool                                            *pgxpool.Pool
	conns, max, acquires, waited, canceled, waiting *prometheus.Desc
}

func (c *poolStats) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.conns, c.max, c.acquires, c.waited, c.canceled, c.waiting} {
		ch <- d
	}
}

func (c *poolStats) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()
	ch <- prometheus.MustNewConstMetric(c.conns, prometheus.GaugeValue, float64(s.AcquiredConns()), "acquired")
	ch <- prometheus.MustNewConstMetric(c.conns, prometheus.GaugeValue, float64(s.IdleConns()), "idle")
	ch <- prometheus.MustNewConstMetric(c.conns, prometheus.GaugeValue, float64(s.ConstructingConns()), "constructing")
	ch <- prometheus.MustNewConstMetric(c.max, prometheus.GaugeValue, float64(s.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.acquires, prometheus.CounterValue, float64(s.AcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.waited, prometheus.CounterValue, float64(s.EmptyAcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.canceled, prometheus.CounterValue, float64(s.CanceledAcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.waiting, prometheus.CounterValue, s.AcquireDuration().Seconds())
}
