package overview

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// allowOnly is an Authorizer that admits every caller to exactly these
// permissions.
func allowOnly(permissions ...string) Authorizer {
	return func(_ context.Context, _ *httpx.Principal, permission string) (bool, error) {
		return slices.Contains(permissions, permission), nil
	}
}

// signInSettings are fixed sign-in settings.
type signInSettings struct{ password, passkey, magicLink, selfRegistration, rememberDevice bool }

func (s signInSettings) AllowedSignInMethods(context.Context, uuid.UUID) (bool, bool, bool, error) {
	return s.password, s.passkey, s.magicLink, nil
}

func (s signInSettings) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return s.selfRegistration, nil
}

func (s signInSettings) RememberDeviceEnabled(context.Context, uuid.UUID) (bool, error) {
	return s.rememberDevice, nil
}
