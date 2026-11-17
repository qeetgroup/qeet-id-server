package rbac

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// grants is a Checker granting a fixed set of permissions.
type grants map[string]bool

func (g grants) Check(_ context.Context, _, _ uuid.UUID, perm string) (bool, error) {
	return g[perm], nil
}

// TestHoldsFollowsTheRouteRules checks that Holds answers as a route gated on
// the permission would: by role for a person, by scope too for an
// application's token, by scope for a machine credential.
func TestHoldsFollowsTheRouteRules(t *testing.T) {
	user, organization := uuid.New(), uuid.New()
	for _, c := range []struct {
		name string
		p    *httpx.Principal
		has  grants
		want bool
	}{
		{"no principal", nil, grants{"role.read": true}, false},
		{"a person with it", &httpx.Principal{UserID: &user, OrganizationID: &organization}, grants{"role.read": true}, true},
		{"a person without it", &httpx.Principal{UserID: &user, OrganizationID: &organization}, grants{}, false},
		{"an app token without the scope", &httpx.Principal{UserID: &user, OrganizationID: &organization, ClientID: "app"}, grants{"role.read": true}, false},
		{"an app token with it", &httpx.Principal{UserID: &user, OrganizationID: &organization, ClientID: "app", Scopes: []string{"role.read"}}, grants{"role.read": true}, true},
		{"an API key with the scope", &httpx.Principal{ActorType: "api_key", Scopes: []string{"role.read"}}, grants{}, true},
		{"an agent without it", &httpx.Principal{ActorType: "agent", Scopes: []string{"group.read"}}, grants{"role.read": true}, false},
		{"an unknown actor", &httpx.Principal{ActorType: "robot", Scopes: []string{"role.read"}}, grants{"role.read": true}, false},
	} {
		if got, err := Holds(context.Background(), c.has, c.p, "role.read"); err != nil || got != c.want {
			t.Errorf("%s: %v, %v; want %v", c.name, got, err, c.want)
		}
	}
}
