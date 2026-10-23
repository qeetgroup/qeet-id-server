package user

import (
	"slices"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestParseImportSource(t *testing.T) {
	cases := []struct {
		in   string
		want ImportSource
		ok   bool
	}{
		{"auth0", SourceAuth0, true},
		{"Auth0", SourceAuth0, true},
		{" cognito ", SourceCognito, true},
		{"azure_b2c", SourceAzureB2C, true},
		{"okta", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseImportSource(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ParseImportSource(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	cases := map[string]string{
		"+1 (555) 123-4567": "+15551234567",
		"555-123-4567":      "5551234567",
		"  +447911123456  ": "+447911123456",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizePhone(in); got != want {
			t.Errorf("normalizePhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAuth0Export(t *testing.T) {
	raw := []byte(`{"email":"alice@example.com","name":"Alice A","phone_number":"+15551234567"}
{"email":"bob@example.com","nickname":"bobby"}
not-json
{"name":"no email here"}
`)
	rows, errs := parseAuth0Export(raw)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (got %+v)", len(rows), rows)
	}
	if rows[0].Email != "alice@example.com" || rows[0].DisplayName != "Alice A" || rows[0].Phone != "+15551234567" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Email != "bob@example.com" || rows[1].DisplayName != "bobby" {
		t.Errorf("row 1 (nickname fallback) = %+v", rows[1])
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %d, want 2 (bad JSON line + missing email line), got %+v", len(errs), errs)
	}
	// Line numbers are 1-based and match the source file.
	if errs[0].Line != 3 {
		t.Errorf("first error line = %d, want 3 (the malformed JSON line)", errs[0].Line)
	}
	if errs[1].Line != 4 {
		t.Errorf("second error line = %d, want 4 (missing email)", errs[1].Line)
	}
}

func TestParseCognitoExport(t *testing.T) {
	raw := []byte("email,name,given_name,family_name,phone_number\n" +
		"alice@example.com,Alice A,,,+15551234567\n" +
		"bob@example.com,,Bob,Jones,\n" +
		",Nobody,,,\n")
	rows, errs := parseCognitoExport(raw)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (got %+v, errs %+v)", len(rows), rows, errs)
	}
	if rows[0].Email != "alice@example.com" || rows[0].DisplayName != "Alice A" || rows[0].Phone != "+15551234567" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Email != "bob@example.com" || rows[1].DisplayName != "Bob Jones" {
		t.Errorf("row 1 (given_name+family_name fallback) = %+v", rows[1])
	}
	if len(errs) != 1 || errs[0].Line != 4 {
		t.Fatalf("errs = %+v, want 1 error on line 4 (missing email)", errs)
	}
}

func TestParseCognitoExport_EmptyFile(t *testing.T) {
	rows, errs := parseCognitoExport([]byte(""))
	if len(rows) != 0 || len(errs) != 0 {
		t.Fatalf("empty file should yield no rows and no errors, got rows=%+v errs=%+v", rows, errs)
	}
}

func TestParseAzureB2CExport(t *testing.T) {
	raw := []byte(`{
		"value": [
			{"displayName": "Alice A", "mail": "alice@example.com", "mobilePhone": "+15551234567"},
			{"displayName": "Bob B", "userPrincipalName": "bob_example.com#EXT#@tenant.onmicrosoft.com",
			 "identities": [{"signInType": "emailAddress", "issuerAssignedId": "bob@example.com"}]},
			{"displayName": "No Email"}
		]
	}`)
	rows, errs := parseAzureB2CExport(raw)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (got %+v)", len(rows), rows)
	}
	if rows[0].Email != "alice@example.com" {
		t.Errorf("row 0 email = %q, want alice@example.com (mail field)", rows[0].Email)
	}
	if rows[1].Email != "bob@example.com" {
		t.Errorf("row 1 email = %q, want bob@example.com (emailAddress identity takes priority over userPrincipalName)", rows[1].Email)
	}
	if len(errs) != 1 || errs[0].Line != 3 {
		t.Fatalf("errs = %+v, want 1 error on line 3 (no email)", errs)
	}
}

func TestParseVendorExport_UnknownSource(t *testing.T) {
	_, errs := ParseVendorExport("okta", []byte("{}"))
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error for an unknown source, got %+v", errs)
	}
}

// parseErrorCases are the ways a vendor adapter refuses an export line or file,
// with the line, code, field and message each reports.
var parseErrorCases = []struct {
	name    string
	source  ImportSource
	raw     string
	line    int
	code    string
	field   string
	message string
}{
	{"auth0 line not JSON", SourceAuth0, "{\"email\":\"a@example.com\"}\nnot-json\n", 2, CodeImportRowMalformed, "", "invalid JSON"},
	{"auth0 email not a string", SourceAuth0, `{"email":42}`, 1, CodeImportRowMalformed, "", "invalid JSON"},
	{"auth0 line too long", SourceAuth0, `{"email":"` + strings.Repeat("x", 1<<20) + `"}`, 1, CodeImportRowMalformed, "", "could not read the export file"},
	{"auth0 missing email", SourceAuth0, `{"name":"No Email"}`, 1, CodeImportFieldMissing, "email", "missing email"},
	{"cognito header unreadable", SourceCognito, "\"email\n", 0, CodeImportRowMalformed, "", "could not read the header row"},
	{"cognito row unreadable", SourceCognito, "email\nbare\"quote@example.com\n", 2, CodeImportRowMalformed, "", "invalid row"},
	{"cognito missing email", SourceCognito, "email,name\n,Nobody\n", 2, CodeImportFieldMissing, "email", "missing email"},
	{"azure export not parsable", SourceAzureB2C, `{"value":[{"mail":42}]}`, 0, CodeImportRowMalformed, "", "invalid JSON"},
	{"azure missing email", SourceAzureB2C, `{"value":[{"displayName":"No Email"}]}`, 1, CodeImportFieldMissing, "email", "missing email (no mail, userPrincipalName, or emailAddress identity)"},
	{"unknown source", "okta", "{}", 0, errs.CodeUserImportSourceInvalid, "", "unknown import source"},
}

// TestParseVendorExport_ErrorCodes checks that every adapter refusal reports
// its listed code and field, and a fixed message that never repeats the
// parser's own error, which can name internal types.
func TestParseVendorExport_ErrorCodes(t *testing.T) {
	for _, tc := range parseErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, rowErrs := ParseVendorExport(tc.source, []byte(tc.raw))
			if len(rowErrs) != 1 {
				t.Fatalf("errors = %+v, want one", rowErrs)
			}
			got := rowErrs[0]
			if got.Code != tc.code || !slices.Contains(importErrorCodes, got.Code) {
				t.Errorf("code = %q, want listed code %q", got.Code, tc.code)
			}
			if got.Line != tc.line || got.Field != tc.field || got.Message != tc.message {
				t.Errorf("error = %+v, want line %d, field %q, message %q", got, tc.line, tc.field, tc.message)
			}
		})
	}
}

// TestVendorRowsKeepTheirFileLine checks that each parsed row remembers its
// line in the export file, past headers, blank lines, quoted line breaks and
// refused lines, and an Azure record its position in value.
func TestVendorRowsKeepTheirFileLine(t *testing.T) {
	cases := []struct {
		name   string
		source ImportSource
		raw    string
		lines  []int
	}{
		{"auth0", SourceAuth0, "{\"email\":\"a@example.com\"}\n\nnot-json\n{\"email\":\"b@example.com\"}\n", []int{1, 4}},
		{"cognito", SourceCognito, "email,name\n\na@example.com,\"Two\nLines\"\n,Nobody\nb@example.com,B\n", []int{3, 6}},
		{"azure_b2c", SourceAzureB2C, `{"value":[{"mail":"a@example.com"},{"displayName":"No Email"},{"mail":"b@example.com"}]}`, []int{1, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, _ := ParseVendorExport(tc.source, []byte(tc.raw))
			if len(rows) != len(tc.lines) {
				t.Fatalf("rows = %+v, want %d", rows, len(tc.lines))
			}
			for i, row := range rows {
				if row.line != tc.lines[i] {
					t.Errorf("row %d (%s) line = %d, want %d", i, row.Email, row.line, tc.lines[i])
				}
			}
		})
	}
}
