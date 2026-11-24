package accessrequest

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
)

// TestNewServiceNeedsItsDependencies checks that the access-request service
// can't be built without whom it grants through, who answers, or how it tells
// them.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	type deps struct {
		roles     RoleGranter
		approvers Approvers
		notifier  notification.Notifier
		phones    PhoneNotifier
	}
	roles, approvers, notifier := stubRoles{}, stubApprovers{}, stubNotifier{}
	for name, d := range map[string]deps{
		"roles":     {nil, approvers, notifier, NoPhones{}},
		"approvers": {roles, nil, notifier, NoPhones{}},
		"notifier":  {roles, approvers, nil, NoPhones{}},
		"phones":    {roles, approvers, notifier, nil},
	} {
		if svc, err := NewService(&pgxpool.Pool{}, d.roles, d.approvers, d.notifier, d.phones); err == nil {
			t.Errorf("NewService without %s: %v, nil; want an error", name, svc)
		}
	}
}

type (
	stubRoles     struct{ RoleGranter }
	stubApprovers struct{ Approvers }
	stubNotifier  struct{ notification.Notifier }
)
