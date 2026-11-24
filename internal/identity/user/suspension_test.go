package user

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuspensionFiltersAreBoundedAndEnumerated(test *testing.T) {
	for _, query := range []string{"cursor=not-a-cursor", "risk=admin", "reason=custom", "source=invalid", "review=automatic"} {
		if _, err := parseSuspensionFilters(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err == nil {
			test.Fatalf("accepted invalid filter %s", query)
		}
	}
	filter, err := parseSuspensionFilters(httptest.NewRequest(http.MethodGet, "/?risk=high&source=scim&review=pending&limit=50", nil))
	if err != nil || filter.Risk != "high" || filter.Source != "scim" || filter.Limit != 50 {
		test.Fatalf("filter mismatch: %+v %v", filter, err)
	}
	// A limit out of range is brought into it, as on every list: the default for 0, the maximum above it.
	for query, want := range map[string]int{"limit=0": 25, "limit=101": 100, "limit=x": 25} {
		if filter, err := parseSuspensionFilters(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err != nil || filter.Limit != want {
			test.Errorf("%s: limit %d, %v; want %d", query, filter.Limit, err, want)
		}
	}
}
