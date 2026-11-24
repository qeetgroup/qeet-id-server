package bootstrap

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// holds is an RBAC checker under which every person holds exactly these
// permissions.
type holds []string

func (h holds) Check(_ context.Context, _, _ uuid.UUID, permission string) (bool, error) {
	for _, p := range h {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// TestOverviewAreasFollowTheRouteGuard checks that the overview shows an area
// to a caller just when the route guard would admit them to a route needing
// its permission: a person by their roles, an application's token only within
// its scopes, an API key by its scopes, and no one without a principal.
func TestOverviewAreasFollowTheRouteGuard(t *testing.T) {
	allowed := overviewAccess(holds{"webhook.read"})
	user, organization := uuid.New(), uuid.New()
	for _, c := range []struct {
		name string
		p    *httpx.Principal
		want bool
	}{
		{"a person holding it", &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user"}, true},
		{"an application's token without the scope", &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user", ClientID: "app"}, false},
		{"an application's token with it", &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user", ClientID: "app", Scopes: []string{"webhook.read"}}, true},
		{"an API key with the scope", &httpx.Principal{OrganizationID: &organization, ActorType: "api_key", Scopes: []string{"webhook.read"}}, true},
		{"an API key without it", &httpx.Principal{OrganizationID: &organization, ActorType: "api_key", Scopes: []string{"user.read"}}, false},
		{"no principal", nil, false},
	} {
		if got, err := allowed(context.Background(), c.p, "webhook.read"); err != nil || got != c.want {
			t.Errorf("%s: %v, %v; want %v", c.name, got, err, c.want)
		}
	}
	if got, _ := allowed(context.Background(), &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user"}, "billing.read"); got {
		t.Error("a person without billing.read is shown billing")
	}
}
