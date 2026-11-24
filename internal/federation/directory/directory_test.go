package directory

import (
	"context"
	"strings"
	"testing"

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

func TestConnectionSourcesCannotReturnAnotherOrganization(test *testing.T) {
	scimSource := &scimFixture{config: &scim.ConfigView{}}
	ldapSource := &ldapFixture{records: []ldap.Connection{{ID: uuid.New(), OrganizationID: uuid.New()}}}
	if records, err := fixtureService(scimSource, ldapSource).List(context.Background(), uuid.New()); err == nil || records != nil {
		test.Fatal("cross-tenant source result was not rejected")
	}
}

// fixtureService is a service over the two sources whose store has no
// database, for checks that end before one is reached.
func fixtureService(scimSource SCIMSource, ldapSource LDAPSource) *Service {
	return &Service{Store: &Store{}, scim: scimSource, ldap: ldapSource}
}

// TestConstructorsRefuseMissingDependencies checks that the store and the
// service are not built without what they read from, naming what is missing.
func TestConstructorsRefuseMissingDependencies(test *testing.T) {
	if _, err := NewStore(nil); err == nil || !strings.Contains(err.Error(), "pool") {
		test.Errorf("store without a pool: %v", err)
	}
	scimSource, ldapSource := &scimFixture{}, &ldapFixture{}
	for _, scenario := range []struct {
		name  string
		store *Store
		scim  SCIMSource
		ldap  LDAPSource
	}{
		{"store", nil, scimSource, ldapSource},
		{"SCIM source", &Store{}, nil, ldapSource},
		{"LDAP source", &Store{}, scimSource, nil},
	} {
		if _, err := NewService(scenario.store, scenario.scim, scenario.ldap); err == nil || !strings.Contains(err.Error(), scenario.name) {
			test.Errorf("service without its %s: %v", scenario.name, err)
		}
	}
	if _, err := NewService(&Store{}, scimSource, ldapSource); err != nil {
		test.Errorf("service with every dependency: %v", err)
	}
}
