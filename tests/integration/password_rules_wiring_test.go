//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
)

// wirePasswordRules builds every password-setting service the way bootstrap
// wires them: one password check (authpolicy ValidateForTenant), which alone
// holds the breach checker (nil = check off).
func wirePasswordRules(t *testing.T, breach *hibp.Checker) passwordPaths {
	t.Helper()
	rules := authpolicy.NewService(testPool)
	rules.SetBreachChecker(breach)

	authSvc, _ := newAuth()
	authSvc.SetRegistrationPolicy(rules)

	recoverySvc := newRecovery(&captureSender{})
	recoverySvc.SetPasswordRules(rules)

	inviteSvc := invite.NewService(testPool, &captureSender{}, time.Hour, "http://app.test")
	inviteSvc.SetPasswordRules(rules)

	return passwordPaths{
		auth:     authSvc,
		recovery: recoverySvc,
		invites:  inviteSvc,
		users: &user.Handler{
			Repo:           user.NewRepository(testPool),
			Validate:       validator.New(validator.WithRequiredStructEnabled()),
			PasswordPolicy: rules.ValidateForTenant,
		},
	}
}
