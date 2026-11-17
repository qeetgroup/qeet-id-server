package rbac

import (
	"context"
	"slices"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Holds reports whether p holds permission in its organization as a route gated on
// that one permission requires (PermissionPolicy): a person through a role, as
// far as an application's token was approved for it; a machine credential as
// a scope. For a handler that shows more to callers who hold more.
func Holds(ctx context.Context, c Checker, p *httpx.Principal, permission string) (bool, error) {
	if p == nil {
		return false, nil
	}
	switch p.ActorType {
	case "", "user":
		if p.UserID == nil || p.OrganizationID == nil {
			return false, nil
		}
		if p.ClientID != "" && !slices.Contains(p.Scopes, permission) {
			return false, nil
		}
		return c.Check(ctx, *p.UserID, *p.OrganizationID, permission)
	case "api_key", "service", "service_principal", "agent":
		return slices.Contains(p.Scopes, permission), nil
	}
	return false, nil
}
