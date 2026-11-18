package threat

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNewServiceNeedsANotifier checks that the anomaly service can't be built
// without the notifier that alerts the person whose account locked.
func TestNewServiceNeedsANotifier(t *testing.T) {
	if svc, err := NewService(&pgxpool.Pool{}, nil); err == nil {
		t.Fatalf("NewService without a notifier: %v, nil; want an error", svc)
	}
}
