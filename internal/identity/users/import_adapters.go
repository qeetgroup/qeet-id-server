package user

// Adapters that turn a vendor's own user-export file (Auth0, AWS Cognito, Azure
// AD B2C) into BulkUserInput rows for runBulkImport.

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ImportSource names a supported vendor export format.
type ImportSource string

const (
	SourceAuth0    ImportSource = "auth0"
	SourceCognito  ImportSource = "cognito"
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

// normalizePhone keeps only the digits and a leading '+', so export formatting
// doesn't fail BulkUserInput's E.164 check. It doesn't add a missing country
// code.
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

// ParseVendorExport parses raw, an export file from source, into import rows
// that remember their line in the file. A row that can't be parsed or has no
// email is returned as a BulkImportError rather than aborting the batch.
func ParseVendorExport(source ImportSource, raw []byte) ([]BulkUserInput, []BulkImportError) {
	switch source {
	case SourceAuth0:
		return parseAuth0Export(raw)
	case SourceCognito:
		return parseCognitoExport(raw)
	case SourceAzureB2C:
		return parseAzureB2CExport(raw)
	default:
		return nil, []BulkImportError{{Code: errs.CodeUserImportSourceInvalid, Message: "unknown import source"}}
	}
}

// auth0Record is one line of Auth0's NDJSON user export. Which fields are
// present depends on the export job.
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
			errs = append(errs, BulkImportError{Line: line, Code: CodeImportRowMalformed, Message: "invalid JSON"})
			continue
		}
		if rec.Email == "" {
			errs = append(errs, BulkImportError{Line: line, Code: CodeImportFieldMissing, Field: "email", Message: "missing email"})
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
			line:        line,
		})
	}
	if sc.Err() != nil {
		errs = append(errs, BulkImportError{Line: line + 1, Code: CodeImportRowMalformed, Message: "could not read the export file"})
	}
	return rows, errs
}

// parseCognitoExport parses an AWS Cognito user-import CSV. Columns are looked up
// by header name, so their order doesn't matter.
func parseCognitoExport(raw []byte) ([]BulkUserInput, []BulkImportError) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1 // tolerate ragged rows rather than aborting the batch
	header, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, []BulkImportError{{Code: CodeImportRowMalformed, Message: "could not read the header row"}}
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
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			var parseErr *csv.ParseError
			line := 0
			if errors.As(err, &parseErr) {
				line = parseErr.StartLine
			}
			errs = append(errs, BulkImportError{Line: line, Code: CodeImportRowMalformed, Message: "invalid row"})
			continue
		}
		// The record's own line in the file, past skipped blank lines and
		// quoted line breaks.
		line, _ := r.FieldPos(0)
		email := get(rec, "email")
		if email == "" {
			errs = append(errs, BulkImportError{Line: line, Code: CodeImportFieldMissing, Field: "email", Message: "missing email"})
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
			line:        line,
		})
	}
	return rows, errs
}

// azureB2CIdentity is a sign-in identity in a Microsoft Graph /users list
// response, the Azure AD B2C export format. B2C local accounts often have no
// mail, so resolveEmail prefers an emailAddress identity.
type azureB2CIdentity struct {
	SignInType       string `json:"signInType"`
	IssuerAssignedID string `json:"issuerAssignedId"`
}

type azureB2CRecord struct {
	DisplayName       string             `json:"displayName"`
	Mail              string             `json:"mail"`
	UserPrincipalName string             `json:"userPrincipalName"`
	MobilePhone       string             `json:"mobilePhone"`
	Identities        []azureB2CIdentity `json:"identities"`
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
		return nil, []BulkImportError{{Code: CodeImportRowMalformed, Message: "invalid JSON"}}
	}
	var rows []BulkUserInput
	var errs []BulkImportError
	for i, rec := range doc.Value {
		line := i + 1
		email := rec.resolveEmail()
		if email == "" {
			errs = append(errs, BulkImportError{Line: line, Code: CodeImportFieldMissing, Field: "email", Message: "missing email (no mail, userPrincipalName, or emailAddress identity)"})
			continue
		}
		rows = append(rows, BulkUserInput{
			Email:       email,
			DisplayName: rec.DisplayName,
			Phone:       normalizePhone(rec.MobilePhone),
			line:        line,
		})
	}
	return rows, errs
}

// importSourceHint lists the supported sources, for the unknown-source error.
func importSourceHint() string {
	return fmt.Sprintf("supported: %s, %s, %s", SourceAuth0, SourceCognito, SourceAzureB2C)
}
