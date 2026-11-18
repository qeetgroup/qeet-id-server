package sales

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNewServiceNeedsASender checks that the service is not built without the
// sender that emails the sales inbox.
func TestNewServiceNeedsASender(t *testing.T) {
	if _, err := NewService(new(pgxpool.Pool), nil, "sales@example.test"); err == nil {
		t.Error("built without a sender")
	}
}
