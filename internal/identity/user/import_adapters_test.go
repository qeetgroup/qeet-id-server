package user

import (
	"slices"
	"strings"
	"testing"
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
			{"displayName": "Bob B", "userPrincipalName": "bob_example.com#EXT#@organization.onmicrosoft.com",
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
	{"unknown source", "okta", "{}", 0, CodeImportSourceInvalid, "", "unknown import source"},
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

// fuzzCheckImportRows fails t unless every parsed row has an email and a phone
// made of digits with at most a leading '+'.
func fuzzCheckImportRows(t *testing.T, rows []BulkUserInput) {
	t.Helper()
	for i, row := range rows {
		if row.Email == "" {
			t.Fatalf("row %d has no email: %+v", i, row)
		}
		digits := strings.TrimPrefix(row.Phone, "+")
		if strings.Trim(digits, "0123456789") != "" {
			t.Fatalf("row %d phone %q is not normalised", i, row.Phone)
		}
	}
}

// fuzzCheckImportErrors fails t unless every parse error carries a listed code.
func fuzzCheckImportErrors(t *testing.T, rowErrs []BulkImportError) {
	t.Helper()
	for i, e := range rowErrs {
		if !slices.Contains(importErrorCodes, e.Code) {
			t.Fatalf("error %d has unlisted code: %+v", i, e)
		}
	}
}

// FuzzParseAuth0Export checks that the Auth0 NDJSON adapter never panics,
// returns only rows with an email and a normalised phone, and gives every
// error a listed code.
func FuzzParseAuth0Export(f *testing.F) {
	for _, seed := range []string{
		`{"user_id":"auth0|1","email":"ada@example.com","name":"Ada Lovelace","phone_number":"+44 (20) 7946-0958"}` + "\n" +
			`{"email":"grace@example.com","nickname":"grace"}` + "\n",
		"{\"email\":\"crlf@example.com\"}\r\n\r\n{\"email\":\"next@example.com\"}",
		`{"email":"","name":"No Email"}`,
		`{"name":"Missing"}`,
		`{"email":42}`,
		`{"email":"a@example.com","phone_number":"++1--555"}`,
		`{"email":"a@example.com","phone_number":"١٢٣"}`,
		`[{"email":"array@example.com"}]`,
		`{"email":"trailing@example.com"} garbage`,
		"{\"email\":\"a@example.com\"}\n\n   \n{",
		"\xef\xbb\xbf{\"email\":\"bom@example.com\"}",
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rows, rowErrs := ParseVendorExport(SourceAuth0, raw)
		fuzzCheckImportRows(t, rows)
		fuzzCheckImportErrors(t, rowErrs)
	})
}

// FuzzParseCognitoExport checks that the Cognito CSV adapter never panics,
// returns only rows with an email and a normalised phone, and gives every
// error a listed code.
func FuzzParseCognitoExport(f *testing.F) {
	for _, seed := range []string{
		"name,given_name,family_name,email,phone_number,cognito:username\n" +
			"Ada Lovelace,Ada,Lovelace,ada@example.com,+442079460958,ada\n" +
			",Grace,Hopper,grace@example.com,,grace\n",
		" Email , Phone_Number \n  spaced@example.com  , (555) 010-0000 \n",
		"email\n\"quoted, with comma\"@example.com\n",
		"email,name\n\"multi\nline\"@example.com,\"Name \"\"Q\"\"\"\n",
		"email,name\na@example.com\n,missing email\nb@example.com,B,extra,cols\n",
		"email\n\"unterminated@example.com\n",
		"email\nbare\"quote@example.com\n",
		"email,email\nfirst@example.com,second@example.com\n",
		"name\nNo Email Column\n",
		"email\r\ncrlf@example.com\r\n",
		"\xef\xbb\xbfemail\nbom@example.com\n",
		"email",
		"\"",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rows, rowErrs := ParseVendorExport(SourceCognito, raw)
		fuzzCheckImportRows(t, rows)
		fuzzCheckImportErrors(t, rowErrs)
	})
}

// FuzzParseAzureB2CExport checks that the Azure AD B2C (Graph /users) adapter
// never panics, returns only rows with an email and a normalised phone, and
// gives every error a listed code.
func FuzzParseAzureB2CExport(f *testing.F) {
	for _, seed := range []string{
		`{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users","value":[` +
			`{"displayName":"Ada","mail":"ada@example.com","mobilePhone":"+44 20 7946 0958"},` +
			`{"displayName":"Local","identities":[{"signInType":"userName","issuerAssignedId":"local"},` +
			`{"signInType":"emailAddress","issuerAssignedId":"local@example.com"}]},` +
			`{"userPrincipalName":"upn@organization.onmicrosoft.com"},` +
			`{"displayName":"Nobody"}]}`,
		`{"value":[{"identities":[{"signInType":"emailAddress","issuerAssignedId":""}],"mail":"fallback@example.com"}]}`,
		`{"value":[{"identities":null,"mail":null}]}`,
		`{"value":[null,{},[]]}`,
		`{"value":{}}`,
		`{"value":null}`,
		`{"value":[{"mail":"a@example.com","mobilePhone":"+1+2+3"}]}`,
		`[{"mail":"array@example.com"}]`,
		`{"value":[{"mail":"a@example.com"}]} trailing`,
		`{}`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rows, rowErrs := ParseVendorExport(SourceAzureB2C, raw)
		fuzzCheckImportRows(t, rows)
		fuzzCheckImportErrors(t, rowErrs)
	})
}
