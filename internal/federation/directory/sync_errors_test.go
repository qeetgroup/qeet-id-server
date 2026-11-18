package directory

import (
	"testing"

	"github.com/google/uuid"
)

func TestRetryEligibilityNeverReplaysProviderRequestsOrCredentials(test *testing.T) {
	base := Event{Status: "failed", Resolution: "open", Operation: "test", ConnectionID: uuid.New().String()}
	if !canRetry(base) {
		test.Fatal("failed LDAP connection test must be retryable")
	}
	for _, operation := range []string{"sign-in", "post", "put", "patch", "delete"} {
		event := base
		event.Operation = operation
		if canRetry(event) {
			test.Fatalf("operation %s must not be replayed", operation)
		}
	}
	base.ConnectionID = "scim:" + uuid.New().String()
	if canRetry(base) {
		test.Fatal("SCIM source requests cannot be replayed by the console")
	}
	base.ConnectionID = uuid.New().String()
	base.Resolution = "retried"
	if canRetry(base) {
		test.Fatal("completed retry must not repeat")
	}
}
