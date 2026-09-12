package user

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuspensionFiltersAreBoundedAndEnumerated(test *testing.T) {
	for _, query := range []string{"limit=0", "limit=101", "offset=-1", "risk=admin", "reason=custom", "source=invalid", "review=automatic"} {
		if _, err := parseSuspensionFilters(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err == nil {
			test.Fatalf("accepted invalid filter %s", query)
		}
	}
	filter, err := parseSuspensionFilters(httptest.NewRequest(http.MethodGet, "/?risk=high&source=scim&review=pending&limit=50", nil))
	if err != nil || filter.Risk != "high" || filter.Source != "scim" || filter.Limit != 50 {
		test.Fatalf("filter mismatch: %+v %v", filter, err)
	}
}
