//go:build integration

package integration

import (
	"context"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
)

// wireSignInLockout mirrors bootstrap: a sign-in's tenant lockout settings
// come from the auth-policy service; the platform configuration is the
// default (5 failures / 15 minutes / 15 minutes, account cap ×4, spraying at
// 30 accounts in 15 minutes).
func wireSignInLockout(svc *auth.Service, rules *authpolicy.Service) {
	svc.SetLockoutConfig(auth.DefaultLockoutConfig())
	svc.SetLockoutSource(func(ctx context.Context, tenantID uuid.UUID) (auth.Lockout, error) {
		l, err := rules.SignInLockout(ctx, tenantID)
		return auth.Lockout(l), err
	})
}
