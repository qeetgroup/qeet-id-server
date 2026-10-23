package user

import (
	"slices"
	"strings"
	"testing"
)

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
			`{"userPrincipalName":"upn@tenant.onmicrosoft.com"},` +
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
