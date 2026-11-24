//go:build integration

// Package contract checks that the API answers as its documents say: every read in api/openapi, sent
// to the whole server by an organization's owner, must answer with a status and a body its document
// describes. A route that answers what isn't documented fails here before a client meets it.
package contract

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/tests/apitest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestEveryReadAnswersAsDocumented sends every GET operation once. Path parameters name the owner's
// organization and account where they can; any other id is one that doesn't exist, so not-found
// answers are checked too. Streams are left out: they don't end.
func TestEveryReadAnswersAsDocumented(t *testing.T) {
	s := apitest.Start(t)
	owner := s.NewOwner()
	sent := 0
	for _, model := range apitest.Models(t) {
		for pair := model.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
			template, item := pair.Key(), pair.Value()
			if item.Get == nil || streams(item.Get) {
				continue
			}
			s.Do(http.MethodGet, fill(template, owner), token(item.Get, owner), nil)
			sent++
		}
	}
	if sent < 150 {
		t.Fatalf("sent %d reads; the documents list more, so the walk is broken", sent)
	}
}

// fill puts a value in each {parameter} of template: the owner's organization and account, or an id
// nothing has.
func fill(template string, o apitest.Owner) string {
	parts := strings.Split(template, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, "{") {
			continue
		}
		switch name := strings.Trim(part, "{}"); {
		case name == "organizationID":
			parts[i] = o.OrganizationID.String()
		case name == "userID" || name == "id" && i > 0 && parts[i-1] == "users":
			parts[i] = o.UserID.String()
		case name == "id" || strings.HasSuffix(name, "ID"):
			parts[i] = uuid.NewString()
		default:
			parts[i] = "unknown"
		}
	}
	return strings.Join(parts, "/")
}

// token is the owner's token for an operation signed in by bearer token, else none: SCIM tokens and
// session cookies are other credentials, so those routes are checked refusing a caller without one.
func token(op *v3.Operation, o apitest.Owner) string {
	for _, requirement := range op.Security {
		if requirement.Requirements == nil {
			continue
		}
		for pair := requirement.Requirements.First(); pair != nil; pair = pair.Next() {
			if pair.Key() == "bearerAuth" {
				return o.Token
			}
		}
	}
	return ""
}

// streams reports whether the operation answers with an event stream.
func streams(op *v3.Operation) bool {
	if op.Responses == nil || op.Responses.Codes == nil {
		return false
	}
	ok := op.Responses.Codes.GetOrZero("200")
	return ok != nil && ok.Content != nil && ok.Content.GetOrZero("text/event-stream") != nil
}
