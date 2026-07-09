// IdP migration adapters: teams leaving Auth0, AWS Cognito, or Azure AD B2C
// can feed that vendor's own user-export file straight into the bulk-import
// pipeline (runBulkImport in bulk.go) instead of hand-converting it to the
// generic BulkUserInput shape first. None of these vendors export a portable
// plaintext password (password hashes use vendor-specific, non-transferable
// schemes), so every imported row lands with no password credential — the
// same "no password" path bulkCreate already supports (see
// Repository.CreateWithCredential, which skips the credential insert
// entirely when the hash is empty). Imported users authenticate via passkey,
// magic link, OTP, or an admin-triggered password reset.
package user

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ImportSource names a supported vendor export format.
type ImportSource string

const (
	SourceAuth0   ImportSource = "auth0"
	SourceCognito ImportSource = "cognito"
	SourceAzureB2C ImportSource = "azure_b2c"
)

// ParseImportSource parses the "source" request parameter.
func ParseImportSource(s string) (ImportSource, bool) {
	switch ImportSource(strings.ToLower(strings.TrimSpace(s))) {
	case SourceAuth0:
		return SourceAuth0, true
	case SourceCognito:
		return SourceCognito, true
	case SourceAzureB2C:
		return SourceAzureB2C, true
	default:
		return "", false
	}
}

// normalizePhone strips common export formatting (spaces, dashes,
// parentheses) so a number that's otherwise valid E.164 isn't rejected by
// BulkUserInput's e164 validation on formatting alone. It does not invent a
// country code — a number missing one still fails validation downstream,
// same as it would from the existing CSV/NDJSON console importer.
func normalizePhone(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == '+' && b.Len() == 0:
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseVendorExport dispatches to the adapter for source, parsing raw into
// the same []BulkUserInput shape the generic bulk-import endpoint accepts.
// Row-level problems (a line that can't be parsed, a record missing an
// email) are returned as BulkImportError so the caller can report them
// exactly like a failed create — parsing never aborts the whole batch.
func ParseVendorExport(source ImportSource, raw []byte) ([]BulkUserInput, []BulkImportError) {
	switch source {
	case SourceAuth0:
		return parseAuth0Export(raw)
	case SourceCognito:
		return parseCognitoExport(raw)
	case SourceAzureB2C:
		return parseAzureB2CExport(raw)
	default:
		return nil, []BulkImportError{{Message: "unknown import source"}}
	}
}

// --- Auth0 ---
//
// Auth0's "Create user export job" produces NDJSON (one JSON object per
// line), with the field set determined by what the export job requested.
// The common, default-ish set: user_id, email, name, nickname, phone_number.
type auth0Record struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	Nickname    string `json:"nickname"`
	PhoneNumber string `json:"phone_number"`
}

func parseAuth0Export(raw []byte) ([]BulkUserInput, []BulkImportError) {
	var rows []BulkUserInput
	var errs []BulkImportError
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var rec auth0Record
		if err := json.Unmarshal([]byte(text), &rec); err != nil {
			errs = append(errs, BulkImportError{Line: line, Message: "invalid JSON: " + err.Error()})
			continue
		}
		if rec.Email == "" {
			errs = append(errs, BulkImportError{Line: line, Message: "missing email"})
			continue
		}
		displayName := rec.Name
		if displayName == "" {
			displayName = rec.Nickname
		}
		rows = append(rows, BulkUserInput{
			Email:       rec.Email,
			DisplayName: displayName,
			Phone:       normalizePhone(rec.PhoneNumber),
		})
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, BulkImportError{Message: "read error: " + err.Error()})
	}
	return rows, errs
}

// --- AWS Cognito ---
//
// Cognito's User Import Job CSV template is a fixed header row (order
// doesn't matter to this parser — columns are looked up by name):
// cognito:username,name,given_name,family_name,middle_name,nickname,
// preferred_username,profile,picture,website,email,email_verified,gender,
// birthdate,zoneinfo,locale,phone_number,phone_number_verified,address,
// updated_at,cognito:mfa_enabled
func parseCognitoExport(raw []byte) ([]BulkUserInput, []BulkImportError) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1 // tolerate ragged rows rather than aborting the batch
	header, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, []BulkImportError{{Message: "read header: " + err.Error()}}
	}
	col := make(map[string]int, len(header))
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(rec []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	var rows []BulkUserInput
	var errs []BulkImportError
	line := 1 // header was line 1
	for {
		line++
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, BulkImportError{Line: line, Message: "invalid row: " + err.Error()})
			continue
		}
		email := get(rec, "email")
		if email == "" {
			errs = append(errs, BulkImportError{Line: line, Message: "missing email"})
			continue
		}
		displayName := get(rec, "name")
		if displayName == "" {
			given, family := get(rec, "given_name"), get(rec, "family_name")
			displayName = strings.TrimSpace(given + " " + family)
		}
		rows = append(rows, BulkUserInput{
			Email:       email,
			DisplayName: displayName,
			Phone:       normalizePhone(get(rec, "phone_number")),
		})
	}
	return rows, errs
}

// --- Azure AD B2C ---
//
// A Microsoft Graph /users (or /b2cIdentityUserFlows) list response:
// {"value": [{"displayName":..., "mail":..., "userPrincipalName":...,
// "mobilePhone":..., "identities": [{"signInType":"emailAddress",
// "issuerAssignedId": "..."}]}]}. B2C local accounts are commonly
// email-identity-only with `mail` unset, so an emailAddress identity (when
// present) takes priority over `mail`/`userPrincipalName`.
type azureB2CIdentity struct {
	SignInType       string `json:"signInType"`
	IssuerAssignedID string `json:"issuerAssignedId"`
}

type azureB2CRecord struct {
	DisplayName       string              `json:"displayName"`
	Mail              string              `json:"mail"`
	UserPrincipalName string              `json:"userPrincipalName"`
	MobilePhone       string              `json:"mobilePhone"`
	Identities        []azureB2CIdentity  `json:"identities"`
}

type azureB2CExport struct {
	Value []azureB2CRecord `json:"value"`
}

func (rec azureB2CRecord) resolveEmail() string {
	for _, id := range rec.Identities {
		if id.SignInType == "emailAddress" && id.IssuerAssignedID != "" {
			return id.IssuerAssignedID
		}
	}
	if rec.Mail != "" {
		return rec.Mail
	}
	return rec.UserPrincipalName
}

func parseAzureB2CExport(raw []byte) ([]BulkUserInput, []BulkImportError) {
	var doc azureB2CExport
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, []BulkImportError{{Message: "invalid JSON: " + err.Error()}}
	}
	var rows []BulkUserInput
	var errs []BulkImportError
	for i, rec := range doc.Value {
		line := i + 1
		email := rec.resolveEmail()
		if email == "" {
			errs = append(errs, BulkImportError{Line: line, Message: "missing email (no mail, userPrincipalName, or emailAddress identity)"})
			continue
		}
		rows = append(rows, BulkUserInput{
			Email:       email,
			DisplayName: rec.DisplayName,
			Phone:       normalizePhone(rec.MobilePhone),
		})
	}
	return rows, errs
}

// importSourceHint is used only in error messages when detection fails.
func importSourceHint() string {
	return fmt.Sprintf("supported: %s, %s, %s", SourceAuth0, SourceCognito, SourceAzureB2C)
}
