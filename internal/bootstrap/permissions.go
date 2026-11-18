package bootstrap

import (
	"maps"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
)

// userPermissionMap maps "METHOD /v1/pattern" routes to the user permission
// they need: <resource>.read for reads and <resource>.write for writes. Routes
// missing from the combined policy table are denied, so every mutation must be
// listed. Each context lists its own routes (wire_<context>.go).
func userPermissionMap() map[string]string {
	return routeTable(accessPermissions(), identityPermissions(), federationPermissions(), developerPermissions(), operationsPermissions())
}

// RoutePolicies returns the authorization policy of every authenticated route,
// keyed "METHOD /v1/pattern", as rbac.Enforce applies it. Each policy names the
// scope an application's token needs on that route.
func RoutePolicies() map[string]rbac.RoutePolicy {
	policies := make(map[string]rbac.RoutePolicy)
	for route, permission := range userPermissionMap() {
		policies[route] = rbac.PermissionPolicy(permission)
	}

	// Explicit user-only routes. These are self-service or personal resources;
	// machine principals cannot inherit them merely by carrying a user id.
	for _, route := range routeList(accessUserOnlyRoutes(), identityUserOnlyRoutes(), federationUserOnlyRoutes(),
		developerUserOnlyRoutes(), operationsUserOnlyRoutes()) {
		policies[route] = rbac.UserOnlyPolicy(accountScope(route))
	}
	// The routes whose policy is neither, which replace any given above.
	maps.Copy(policies, routeTable(accessPolicies(), federationPolicies(), developerPolicies(), operationsPolicies()))
	return policies
}

// routeTable merges the contexts' tables of one kind into one, refusing a
// route that two of them name: each route has one owner.
func routeTable[V any](tables ...map[string]V) map[string]V {
	out := map[string]V{}
	for _, table := range tables {
		for route, v := range table {
			if _, dup := out[route]; dup {
				panic("bootstrap: two contexts list the route " + route)
			}
			out[route] = v
		}
	}
	return out
}

// routeList joins the contexts' lists of one kind, refusing a route that two
// of them name, or one names twice.
func routeList(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, route := range list {
			if seen[route] {
				panic("bootstrap: the route " + route + " is listed twice")
			}
			seen[route] = true
			out = append(out, route)
		}
	}
	return out
}

// accountScope is the scope an application's token needs on a route of the
// user's own account: account.read to read it, account.write to change it.
func accountScope(route string) string {
	if strings.HasPrefix(route, "GET ") {
		return "account.read"
	}
	return "account.write"
}
