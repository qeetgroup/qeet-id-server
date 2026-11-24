package paging

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestResultJSON checks that next_cursor and truncated are left out unless set,
// that items is never null, and that an embedding body is flattened.
func TestResultJSON(t *testing.T) {
	type page struct {
		Result[int]
		Total int `json:"total"`
	}
	for _, c := range []struct {
		name string
		body any
		want string
	}{
		{"last page", Page[int](nil, ""), `{"items":[]}`},
		{"more pages", Page([]int{1}, "c"), `{"items":[1],"next_cursor":"c"}`},
		{"truncated list", List(make([]int, MaxListItems+1)).Truncated, `true`},
		{"whole list", List([]int{1, 2}), `{"items":[1,2]}`},
		{"empty list", List[int](nil), `{"items":[]}`},
		{"embedded", page{Page([]int{1}, ""), 7}, `{"items":[1],"total":7}`},
	} {
		got, err := json.Marshal(c.body)
		if err != nil || string(got) != c.want {
			t.Errorf("%s: %s, %v; want %s", c.name, got, err, c.want)
		}
	}
}

// TestPageOfNext checks that Page takes Next's two results directly.
func TestPageOfNext(t *testing.T) {
	at := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	res := Page(Next(ids, 2, func(id uuid.UUID) (time.Time, uuid.UUID) { return at, id }))
	if len(res.Items) != 2 || res.NextCursor != EncodeTimeUUID(at, ids[1]) {
		t.Errorf("Page(Next(…)) = %d items, cursor %q", len(res.Items), res.NextCursor)
	}
}

// TestLimit checks the page size a limit parameter gives.
func TestLimit(t *testing.T) {
	for raw, want := range map[string]int{"": 50, "abc": 50, "0": 50, "-3": 50, "1": 1, "100": 100, "101": 100, "99999999999999999999": 50} {
		if got := Limit(url.Values{"limit": {raw}}, 50, 100); got != want {
			t.Errorf("limit=%q: %d; want %d", raw, got, want)
		}
	}
	if got := Limit(url.Values{}, 20, 100); got != 20 {
		t.Errorf("no limit: %d; want 20", got)
	}
}
