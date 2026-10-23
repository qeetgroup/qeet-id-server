//go:build integration

package postgres_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestPoolCollectorReportsThePool checks that the pool metrics carry its limit
// and count its acquires.
func TestPoolCollectorReportsThePool(t *testing.T) {
	pool := dbtest.Pool(t)
	if err := pool.Ping(dbtest.Context(t)); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(postgres.PoolCollector(pool))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		m := f.GetMetric()[0]
		if m.GetGauge() != nil {
			got[f.GetName()] = m.GetGauge().GetValue()
		} else {
			got[f.GetName()] = m.GetCounter().GetValue()
		}
	}
	if got["db_pool_max_connections"] != float64(pool.Stat().MaxConns()) || got["db_pool_acquires_total"] < 1 {
		t.Errorf("pool metrics %v, want the limit %d and an acquire", got, pool.Stat().MaxConns())
	}
}
