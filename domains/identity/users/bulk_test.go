package user

import (
	"context"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
)

// TestRunBulkImport_PartialSuccess verifies that bad and duplicate rows are
// reported per-row without failing the whole batch, that create is only called
// for rows that pass validation, and that line numbers + the conflict message
// are surfaced correctly.
func TestRunBulkImport_PartialSuccess(t *testing.T) {
	v := validator.New()
	tenant := uuid.New()
	rows := []BulkUserInput{
		{Email: "a@example.com", DisplayName: "A"},  // 1: ok
		{Email: "not-an-email"},                     // 2: invalid email
		{Email: "dupe@example.com"},                 // 3: creator returns conflict
		{Email: "b@example.com", Password: "short"}, // 4: password too short
		{Email: "c@example.com"},                    // 5: ok
	}

	var calls int
	create := func(_ context.Context, in CreateInput) (*User, error) {
		calls++
		if in.TenantID != tenant {
			t.Errorf("create got tenant %s, want %s", in.TenantID, tenant)
		}
		if in.Email == "dupe@example.com" {
			return nil, errs.ErrConflict
		}
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}

	res, created := runBulkImport(context.Background(), v, tenant, rows, create)

	if res.Succeeded != 2 {
		t.Errorf("Succeeded = %d, want 2", res.Succeeded)
	}
	if res.Failed != 3 {
		t.Errorf("Failed = %d, want 3", res.Failed)
	}
	if len(created) != 2 {
		t.Errorf("len(created) = %d, want 2", len(created))
	}
	// create must run only for the 3 rows that passed validation (1, 3, 5).
	if calls != 3 {
		t.Errorf("create called %d times, want 3 (validation-failed rows must not reach create)", calls)
	}
	if len(res.Errors) != 3 {
		t.Fatalf("len(Errors) = %d, want 3", len(res.Errors))
	}
	// Errors preserve the 1-based row order: lines 2, 3, 4.
	wantLines := []int{2, 3, 4}
	for i, e := range res.Errors {
		if e.Line != wantLines[i] {
			t.Errorf("Errors[%d].Line = %d, want %d", i, e.Line, wantLines[i])
		}
	}
	// The duplicate row (line 3) reports a conflict-specific message.
	if got := res.Errors[1]; got.Email != "dupe@example.com" || !strings.Contains(got.Message, "already exists") {
		t.Errorf("conflict error = %+v, want dupe@example.com / 'already exists'", got)
	}
}

// TestRunBulkImport_AllValid covers the happy path.
func TestRunBulkImport_AllValid(t *testing.T) {
	v := validator.New()
	tenant := uuid.New()
	rows := []BulkUserInput{{Email: "x@example.com"}, {Email: "y@example.com"}}
	create := func(_ context.Context, in CreateInput) (*User, error) {
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}
	res, created := runBulkImport(context.Background(), v, tenant, rows, create)
	if res.Succeeded != 2 || res.Failed != 0 || len(res.Errors) != 0 || len(created) != 2 {
		t.Errorf("all-valid: got succeeded=%d failed=%d errors=%d created=%d, want 2/0/0/2",
			res.Succeeded, res.Failed, len(res.Errors), len(created))
	}
}
