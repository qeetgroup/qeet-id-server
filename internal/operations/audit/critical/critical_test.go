package critical

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

type fakeAudit struct {
	filter audit.ListFilter
	rows   []audit.Row
}

func (f *fakeAudit) List(_ context.Context, _ uuid.UUID, _ int, _ string, filter audit.ListFilter) ([]audit.Row, string, int, error) {
	f.filter = filter
	return f.rows, "", len(f.rows), nil
}

type fakeAnomalies struct {
	status string
	rows   []anomaly.Anomaly
}

func (f *fakeAnomalies) List(_ context.Context, _ uuid.UUID, status string, _ int) ([]anomaly.Anomaly, error) {
	f.status = status
	return f.rows, nil
}

// TestCriticalEventsMergeNewestFirst checks the list asks for the critical
// actions since the window's start and open anomalies, levels each, drops
// anomalies older than the window, and orders everything newest first.
func TestCriticalEventsMergeNewestFirst(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	a := &fakeAudit{rows: []audit.Row{
		{ID: uuid.New(), Action: "user.suspended", CreatedAt: now.Add(-2 * time.Hour)},
		{ID: uuid.New(), Action: "role.assigned", CreatedAt: now.Add(-30 * time.Minute)},
	}}
	an := &fakeAnomalies{rows: []anomaly.Anomaly{
		{ID: uuid.New(), Action: "auth.login", Score: 0.92, EventAt: now.Add(-3 * time.Minute), Reasons: []string{"new_ip"}},
		{ID: uuid.New(), Action: "auth.login", Score: 0.7, EventAt: now.Add(-1 * time.Hour)},
		{ID: uuid.New(), Action: "auth.login", Score: 0.99, EventAt: now.Add(-30 * time.Hour)},
	}}
	s := NewService(a, an)
	s.now = func() time.Time { return now }
	out, err := s.List(context.Background(), uuid.New(), 24)
	if err != nil {
		t.Fatal(err)
	}
	if an.status != "open" || a.filter.From == nil || !a.filter.From.Equal(now.Add(-24*time.Hour)) || len(a.filter.Actions) != len(Actions) {
		t.Errorf("asked audit %+v and anomalies %q", a.filter, an.status)
	}
	want := []struct{ source, level string }{{"anomaly", High}, {"audit", Medium}, {"anomaly", Medium}, {"audit", High}}
	if len(out) != len(want) {
		t.Fatalf("got %d events, want %d (the 30-hour-old anomaly is outside the window)", len(out), len(want))
	}
	for i, w := range want {
		if out[i].Source != w.source || out[i].Level != w.level {
			t.Errorf("event %d is %s/%s, want %s/%s", i, out[i].Source, out[i].Level, w.source, w.level)
		}
	}
	if _, err := s.List(context.Background(), uuid.New(), 0); !errors.Is(err, errs.ErrBadRequest) {
		t.Errorf("0 hours: %v", err)
	}
}
