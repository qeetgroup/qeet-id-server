package directory

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestOperationClassificationAndFilterBounds(test *testing.T) {
	for _, status := range []int{200, 201, 204} {
		outcome, _, code, _, _ := classifyOperation("post", status)
		if outcome != "success" || code != "" {
			test.Fatalf("status %d misclassified", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 409, 422, 429, 500, 502} {
		outcome, category, code, message, severity := classifyOperation("post", status)
		if outcome != "failed" || category == "" || code == "" || message == "" || severity == "" {
			test.Fatalf("status %d lacks safe error metadata", status)
		}
	}
	// At sign-in a person's refused credentials are a warning; the directory
	// itself refusing (403) or failing stays an error.
	if outcome, category, _, _, severity := classifyOperation("sign-in", 401); outcome != "warning" || category != "credentials" || severity != "" {
		test.Fatalf("a refused sign-in classified %s/%s/%s, want a warning without severity", outcome, category, severity)
	}
	for _, status := range []int{403, 502} {
		if outcome, _, _, _, severity := classifyOperation("sign-in", status); outcome != "failed" || severity != "critical" {
			test.Fatalf("sign-in status %d classified %s/%s, want a critical failure", status, outcome, severity)
		}
	}
	for _, query := range []string{"days=0", "days=91", "limit=0", "limit=101", "cursor=not-a-cursor", "status=invalid"} {
		if _, err := parseEventFilter(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err == nil {
			test.Fatalf("accepted invalid filter %s", query)
		}
	}
	at, id := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC), uuid.New()
	filter, err := parseEventFilter(httptest.NewRequest(http.MethodGet, "/?days=30&limit=50&cursor="+paging.EncodeTimeUUID(at, id)+"&status=failed", nil))
	if err != nil || filter.Limit != 50 || !filter.After.Set || !filter.After.Time.Equal(at) || filter.After.ID != id || filter.Status != "failed" {
		test.Fatalf("invalid parsed filter: %+v %v", filter, err)
	}
}
