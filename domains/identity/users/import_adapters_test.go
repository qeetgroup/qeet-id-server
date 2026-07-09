package user

import "testing"

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
