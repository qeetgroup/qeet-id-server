package directory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
)

type scimFixture struct {
	config        *scim.ConfigView
	organizations []uuid.UUID
}

func (source *scimFixture) Config(_ context.Context, organizationID uuid.UUID) (*scim.ConfigView, error) {
	source.organizations = append(source.organizations, organizationID)
	return source.config, nil
}

type ldapFixture struct {
	records       []ldap.Connection
	organizations []uuid.UUID
	tests         int
	testError     error
}

func (source *ldapFixture) TestConnection(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	source.tests++
	return source.testError
}

func (source *ldapFixture) List(_ context.Context, organizationID uuid.UUID) ([]ldap.Connection, error) {
	source.organizations = append(source.organizations, organizationID)
	return source.records, nil
}

func TestConnectionSnapshotDoesNotInventHealthOrExposeCredentials(test *testing.T) {
	organizationID := uuid.New()
	usedAt := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	scimSource := &scimFixture{config: &scim.ConfigView{
		TokenSet: true, TokenPrefix: "private-prefix", LastUsedAt: &usedAt, ProvisionedCount: 128,
	}}
	ldapSource := &ldapFixture{records: []ldap.Connection{{
		ID: uuid.New(), OrganizationID: organizationID, Name: "Corporate directory", Status: "active",
		ServerURL: "ldaps://directory.example.test", BindDN: "private-bind-dn", LastLoginAt: &usedAt,
	}}}
	records, err := NewService(scimSource, ldapSource).List(context.Background(), organizationID)
	if err != nil {
		test.Fatal(err)
	}
	if len(records) != 2 {
		test.Fatalf("got %d connections, want 2", len(records))
	}
	for _, record := range records {
		if record.Health != "unknown" || record.LastSyncAt != nil || record.Environment != nil {
			test.Fatalf("configuration was presented as sync telemetry: %+v", record)
		}
		if record.LastActivityAt == nil || !record.LastActivityAt.Equal(usedAt) {
			test.Fatal("last activity was not retained")
		}
	}
	raw, err := json.Marshal(records)
	if err != nil {
		test.Fatal(err)
	}
	for _, prohibited := range []string{"private-prefix", "private-bind-dn", "bind_password", "token_prefix"} {
		if strings.Contains(string(raw), prohibited) {
			test.Fatalf("connection snapshot exposed %q", prohibited)
		}
	}
}

func TestConnectionSourcesCannotReturnAnotherOrganization(test *testing.T) {
	scimSource := &scimFixture{config: &scim.ConfigView{}}
	ldapSource := &ldapFixture{records: []ldap.Connection{{ID: uuid.New(), OrganizationID: uuid.New()}}}
	if records, err := NewService(scimSource, ldapSource).List(context.Background(), uuid.New()); err == nil || records != nil {
		test.Fatal("cross-tenant source result was not rejected")
	}
}
