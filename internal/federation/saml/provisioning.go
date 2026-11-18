package saml

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// assertion is what a validated SAML assertion says about the person it signs
// in: groupsWithheld means the IdP left their groups out (assertedGroups).
type assertion struct {
	subject, email, name string
	groups               []string
	groupsWithheld       bool
}

// findOrCreateUser returns the account the connection signs in for the
// assertion, found, adopted or created by identitylink's rules, which also
// keep its profile and groups in step with the assertion, recorded as actor's.
func (s *Service) findOrCreateUser(ctx context.Context, organizationID, connID uuid.UUID, a assertion, actor audit.Actor) (uuid.UUID, error) {
	return s.link.Resolve(ctx, provision.Source{OrganizationID: organizationID, Provider: provider, ConnectionID: connID},
		provision.Person{Subject: a.subject, Email: a.email, Name: a.name, Groups: a.groups, GroupsWithheld: a.groupsWithheld}, actor)
}
