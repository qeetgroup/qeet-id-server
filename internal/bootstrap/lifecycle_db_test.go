//go:build integration

package bootstrap

import (
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestRecordShutdownAuditsTheStop checks that a stop leaves one platform audit
// event, by the system, about no resource, saying how the stop went.
func TestRecordShutdownAuditsTheStop(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	service := "shutdown-" + time.Now().Format("150405.000000000")
	recordShutdown(ctx, pool, &config.Config{ServiceName: service, ServiceEnv: "dev"}, shutdownReport{duration: 2 * time.Second, dropped: 3})
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'system.shutdown' AND organization_id IS NULL
		AND actor_type = 'system' AND actor_user_id IS NULL AND resource_id IS NULL AND metadata->>'service' = $1
		AND (metadata->>'duration_ms')::int = 2000 AND (metadata->>'dropped_requests')::int = 3`, service); n != 1 {
		t.Errorf("shutdown events: %d, want 1", n)
	}
}
