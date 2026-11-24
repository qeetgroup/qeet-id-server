package domainverify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestLoginDomainWithoutAHostListsNoRecords checks that an organization with no custom login
// domain is answered with an empty records list, as the API document promises, not null.
func TestLoginDomainWithoutAHostListsNoRecords(t *testing.T) {
	st := (&Service{}).loginDomainStatus(context.Background(), uuid.New(), "")
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"records":[]`) {
		t.Errorf("answer %s, want \"records\":[]", b)
	}
}
