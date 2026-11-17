package bootstrap

import "testing"

// TestTakingAuthorityAwayNeedsStepUp checks that the routes taking a role away
// through a group need a fresh second factor, as giving one does.
func TestTakingAuthorityAwayNeedsStepUp(t *testing.T) {
	routes := StepUpRoutes()
	for _, route := range []string{
		"DELETE /v1/groups/{id}",
		"DELETE /v1/groups/{id}/members/{userID}",
		"DELETE /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}",
	} {
		if _, ok := routes[route]; !ok {
			t.Errorf("%s needs no step-up", route)
		}
	}
}
