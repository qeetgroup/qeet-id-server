package user

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRunBulkImport_PartialSuccess checks that bad and duplicate rows are
// reported by line without failing the batch, and that only valid rows reach
// create.
func TestRunBulkImport_PartialSuccess(t *testing.T) {
	v := validator.New()
	tenant := uuid.New()
	rows := []BulkUserInput{
		{Email: "a@example.com", DisplayName: "A"},                   // 1: ok
		{Email: "not-an-email"},                                      // 2: invalid email
		{Email: "dupe@example.com"},                                  // 3: creator returns conflict
		{Email: "b@example.com", Password: strings.Repeat("x", 257)}, // 4: password over max=256
		{Email: "c@example.com"},                                     // 5: ok
	}

	var calls int
	create := func(_ context.Context, in CreateInput) (*User, error) {
		calls++
		if in.TenantID != tenant {
			t.Errorf("create got tenant %s, want %s", in.TenantID, tenant)
		}
		if in.Email == "dupe@example.com" {
			return nil, errs.ErrAuthEmailExists
		}
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}

	res := runBulkImport(context.Background(), v, tenant, rows, create)

	if res.Succeeded != 2 {
		t.Errorf("Succeeded = %d, want 2", res.Succeeded)
	}
	if res.Failed != 3 {
		t.Errorf("Failed = %d, want 3", res.Failed)
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

// TestRunBulkImport_AllValid checks that every valid row is created.
func TestRunBulkImport_AllValid(t *testing.T) {
	v := validator.New()
	tenant := uuid.New()
	rows := []BulkUserInput{{Email: "x@example.com"}, {Email: "y@example.com"}}
	create := func(_ context.Context, in CreateInput) (*User, error) {
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}
	res := runBulkImport(context.Background(), v, tenant, rows, create)
	if res.Succeeded != 2 || res.Failed != 0 || len(res.Errors) != 0 {
		t.Errorf("all-valid: got succeeded=%d failed=%d errors=%d, want 2/0/0",
			res.Succeeded, res.Failed, len(res.Errors))
	}
}

// TestRunBulkImport_RefusedPasswordReportsTheRule checks that a row whose
// password is refused reports the rule it broke, not a generic failure.
func TestRunBulkImport_RefusedPasswordReportsTheRule(t *testing.T) {
	tenant := uuid.New()
	rows := []BulkUserInput{
		{Email: "ok@example.com", Password: "Correct-Horse-Battery-9"},
		{Email: "nosymbol@example.com", Password: "CorrectHorseBattery99"},
	}
	create := func(_ context.Context, in CreateInput) (*User, error) {
		if in.Password == "CorrectHorseBattery99" {
			return nil, errs.ErrAuthPolicyPasswordNoSymbol
		}
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}
	res := runBulkImport(context.Background(), validator.New(), tenant, rows, create)
	if res.Succeeded != 1 || res.Failed != 1 || len(res.Errors) != 1 {
		t.Fatalf("result = %+v, want 1 created and 1 refused", res)
	}
	if got := res.Errors[0]; got.Line != 2 || got.Message != errs.ErrAuthPolicyPasswordNoSymbol.Message {
		t.Errorf("row error = %+v, want line 2 with %q", got, errs.ErrAuthPolicyPasswordNoSymbol.Message)
	}
}

// jsonNamedValidator names fields by their JSON tag, as the server's does.
func jsonNamedValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		return name
	})
	return v
}

// dbDetail stands in for the internal detail a failed create can carry.
const dbDetail = `ERROR: duplicate key value violates unique constraint "users_email_key" (SQLSTATE 23505)`

// rowErrorCases are the ways runBulkImport refuses a row, with the code, field
// and message each reports. A validation message is the JSON-named one.
var rowErrorCases = []struct {
	name      string
	row       BulkUserInput
	createErr error
	code      string
	field     string
	message   string
}{
	{"missing email", BulkUserInput{}, nil, CodeImportFieldMissing, "email", "invalid row: email failed required"},
	{"invalid email", BulkUserInput{Email: "not-an-email"}, nil, CodeImportFieldInvalid, "email", "invalid row: email failed email"},
	{"password too long", BulkUserInput{Email: "row@example.com", Password: strings.Repeat("x", 257)}, nil, CodeImportFieldTooLong, "password", "invalid row: password failed max"},
	{"display name too long", BulkUserInput{Email: "row@example.com", DisplayName: strings.Repeat("x", 201)}, nil, CodeImportFieldTooLong, "display_name", "invalid row: display_name failed max"},
	{"invalid phone", BulkUserInput{Email: "row@example.com", Phone: "555-0100"}, nil, CodeImportFieldInvalid, "phone", "invalid row: phone failed e164"},
	{"duplicate email", BulkUserInput{Email: "row@example.com"}, errs.ErrAuthEmailExists, errs.CodeAuthEmailExists, "email", "a user with this email already exists"},
	{"duplicate email with detail", BulkUserInput{Email: "row@example.com"}, errs.ErrAuthEmailExists.WithDetail(dbDetail), errs.CodeAuthEmailExists, "email", "a user with this email already exists"},
	{"password too short", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPolicyPasswordTooShort, errs.CodeAuthPolicyPasswordTooShort, "password", errs.ErrAuthPolicyPasswordTooShort.Message},
	{"password without uppercase", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPolicyPasswordNoUppercase, errs.CodeAuthPolicyPasswordNoUppercase, "password", errs.ErrAuthPolicyPasswordNoUppercase.Message},
	{"password without number", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPolicyPasswordNoNumber, errs.CodeAuthPolicyPasswordNoNumber, "password", errs.ErrAuthPolicyPasswordNoNumber.Message},
	{"password without symbol", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPolicyPasswordNoSymbol, errs.CodeAuthPolicyPasswordNoSymbol, "password", errs.ErrAuthPolicyPasswordNoSymbol.Message},
	{"breached password", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPolicyPasswordBreached, errs.CodeAuthPolicyPasswordBreached, "password", errs.ErrAuthPolicyPasswordBreached.Message},
	{"weak password", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrAuthPasswordWeak.WithMessage("Your password contains your email address."), errs.CodeAuthPasswordWeak, "password", "Your password contains your email address."},
	{"database failure", BulkUserInput{Email: "row@example.com"}, errors.New(dbDetail), errs.CodeInternal, "", "could not create user"},
	{"wrapped database failure", BulkUserInput{Email: "row@example.com"}, errs.ErrInternalServer.Wrap(errors.New(dbDetail)), errs.CodeInternal, "", "could not create user"},
	{"other refusal", BulkUserInput{Email: "row@example.com"}, errs.ErrBadRequest.WithDetail(dbDetail), errs.CodeInternal, "", "could not create user"},
	{"password check unavailable", BulkUserInput{Email: "row@example.com", Password: "x"}, errs.ErrNotImplemented, errs.CodeInternal, "", "could not create user"},
}

// TestRunBulkImport_RowErrorCodes checks that every refused row reports its
// listed code and the JSON field it concerns, whichever way the validator
// names fields, and that a failed create never shows its cause.
func TestRunBulkImport_RowErrorCodes(t *testing.T) {
	for _, tc := range rowErrorCases {
		for _, named := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json_named=%v", tc.name, named), func(t *testing.T) {
				v := validator.New()
				if named {
					v = jsonNamedValidator()
				}
				create := func(context.Context, CreateInput) (*User, error) {
					if tc.createErr == nil {
						t.Fatal("a row that fails validation reached create")
					}
					return nil, tc.createErr
				}
				res := runBulkImport(context.Background(), v, uuid.New(), []BulkUserInput{tc.row}, create)
				if res.Failed != 1 || len(res.Errors) != 1 {
					t.Fatalf("result = %+v, want one refused row", res)
				}
				got := res.Errors[0]
				if got.Code != tc.code || !slices.Contains(importErrorCodes, got.Code) {
					t.Errorf("code = %q, want listed code %q", got.Code, tc.code)
				}
				if got.Field != tc.field {
					t.Errorf("field = %q, want %q", got.Field, tc.field)
				}
				if (named || tc.createErr != nil) && got.Message != tc.message {
					t.Errorf("message = %q, want %q", got.Message, tc.message)
				}
				if strings.Contains(got.Message, "SQLSTATE") || strings.Contains(got.Code, "SQLSTATE") {
					t.Errorf("row error %+v shows the failure's cause", got)
				}
			})
		}
	}
}

// TestImportErrorCodesAreAllEmitted checks that the row and parse cases cover
// importErrorCodes exactly, so the documented list matches what is emitted.
func TestImportErrorCodesAreAllEmitted(t *testing.T) {
	emitted := map[string]bool{}
	for _, tc := range rowErrorCases {
		emitted[tc.code] = true
	}
	for _, tc := range parseErrorCases {
		emitted[tc.code] = true
	}
	for _, code := range importErrorCodes {
		if !emitted[code] {
			t.Errorf("no case emits listed code %q", code)
		}
		delete(emitted, code)
	}
	for code := range emitted {
		t.Errorf("code %q is emitted but not in importErrorCodes", code)
	}
}

// TestRunBulkImport_ExportRowsReportTheirFileLine checks that a row from an
// export file is reported at its line in the file, and a JSON row at its
// position in the array.
func TestRunBulkImport_ExportRowsReportTheirFileLine(t *testing.T) {
	rows := []BulkUserInput{
		{Email: "a@example.com", line: 3},
		{Email: "not-an-email", line: 7},
		{Email: "dupe@example.com", line: 9},
		{Email: "also-not-an-email"},
	}
	create := func(_ context.Context, in CreateInput) (*User, error) {
		if in.Email == "dupe@example.com" {
			return nil, errs.ErrAuthEmailExists
		}
		return &User{ID: uuid.New(), TenantID: in.TenantID, Email: in.Email}, nil
	}
	res := runBulkImport(context.Background(), validator.New(), uuid.New(), rows, create)
	var lines []int
	for _, e := range res.Errors {
		lines = append(lines, e.Line)
	}
	if !slices.Equal(lines, []int{7, 9, 4}) {
		t.Errorf("error lines = %v, want [7 9 4]", lines)
	}
}
