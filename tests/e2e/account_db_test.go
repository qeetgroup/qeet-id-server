//go:build integration

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/tests/apitest"
)

// pair is the tokens a sign-in or renewal answers with.
type pair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func renew(t *testing.T, s *apitest.Server, refresh string) *apitest.Response {
	t.Helper()
	return s.Do(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refresh_token": refresh})
}

// TestSignUpSignInRenewAndSignOut follows one person: signing up opens a session; signing in opens a
// second; renewing rotates its refresh token; presenting a rotated token again ends that session
// (taken as theft) but not the first; signing out ends the first.
func TestSignUpSignInRenewAndSignOut(t *testing.T) {
	s := apitest.Start(t)
	email, password := dbtest.Unique("person")+"@example.test", "corr3ct-h0rse-battery-staple"
	userID, signupToken, signupRefresh := s.SignUp(email, password)

	var me struct {
		UserID uuid.UUID `json:"user_id"`
		Actor  string    `json:"actor"`
	}
	s.Do(http.MethodGet, "/v1/auth/me", signupToken, nil).Want(t, http.StatusOK).JSON(t, &me)
	if me.UserID != userID || me.Actor != "user" {
		t.Fatalf("me: %+v, want the user %s", me, userID)
	}

	var signedIn, renewed, renewedAgain pair
	s.Do(http.MethodPost, "/v1/auth/login", "", map[string]string{"email": email, "password": password}).Want(t, http.StatusOK).JSON(t, &signedIn)
	renew(t, s, signedIn.RefreshToken).Want(t, http.StatusOK).JSON(t, &renewed)
	renew(t, s, renewed.RefreshToken).Want(t, http.StatusOK).JSON(t, &renewedAgain)
	if renewedAgain.RefreshToken == renewed.RefreshToken || renewed.RefreshToken == signedIn.RefreshToken {
		t.Fatal("renewing returned the same refresh token: it must rotate")
	}

	// The first rotated token, whose replacement has been used: theft, so the session ends.
	if res := renew(t, s, signedIn.RefreshToken); res.Status != http.StatusUnauthorized || !strings.Contains(string(res.Body), "auth.session_revoked") {
		t.Fatalf("reusing a rotated refresh token: %d %s, want 401 auth.session_revoked", res.Status, res.Body)
	}
	renew(t, s, renewedAgain.RefreshToken).Want(t, http.StatusUnauthorized)
	s.Do(http.MethodGet, "/v1/auth/me", renewedAgain.AccessToken, nil).Want(t, http.StatusUnauthorized)

	// The sign-up session is another session: untouched, until it signs out.
	s.Do(http.MethodGet, "/v1/auth/me", signupToken, nil).Want(t, http.StatusOK)
	s.Do(http.MethodPost, "/v1/auth/logout", signupToken, nil).Want(t, http.StatusOK)
	s.Do(http.MethodGet, "/v1/auth/me", signupToken, nil).Want(t, http.StatusUnauthorized)
	renew(t, s, signupRefresh).Want(t, http.StatusUnauthorized)
}

// TestWrongPasswordIsRefusedLikeAnUnknownAccount checks that a wrong password and an address with
// no account get the same answer, so sign-in can't be used to find out who has an account.
func TestWrongPasswordIsRefusedLikeAnUnknownAccount(t *testing.T) {
	s := apitest.Start(t)
	email := dbtest.Unique("person") + "@example.test"
	s.SignUp(email, "corr3ct-h0rse-battery-staple")

	wrong := s.Do(http.MethodPost, "/v1/auth/login", "", map[string]string{"email": email, "password": "not-the-password-1"}).Want(t, http.StatusUnauthorized)
	unknown := s.Do(http.MethodPost, "/v1/auth/login", "", map[string]string{"email": dbtest.Unique("nobody") + "@example.test", "password": "not-the-password-1"}).
		Want(t, http.StatusUnauthorized)
	var a, b struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	wrong.JSON(t, &a)
	unknown.JSON(t, &b)
	if a.Error != b.Error {
		t.Errorf("wrong password answered %+v, unknown address %+v: they must match", a.Error, b.Error)
	}
}
