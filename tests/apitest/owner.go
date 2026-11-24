//go:build integration

package apitest

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// Owner is a person who signed up and created an organization through the API, so they hold its
// built-in owner role. Token acts in that organization.
type Owner struct {
	UserID, OrganizationID    uuid.UUID
	Email, Password           string
	Token, RefreshToken, Slug string
}

// session is the token pair the sign-up, sign-in and organization calls answer with.
type session struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
}

// SignUp registers a new person through the API and returns their account-level session.
func (s *Server) SignUp(email, password string) (uuid.UUID, string, string) {
	s.t.Helper()
	var out session
	s.Do(http.MethodPost, "/v1/auth/signup", "", map[string]string{"email": email, "password": password, "display_name": "Test Person"}).
		Want(s.t, http.StatusCreated).JSON(s.t, &out)
	return out.UserID, out.AccessToken, out.RefreshToken
}

// NewOwner signs a new person up, marks their address verified (what entering the emailed code
// does) and has them create an organization on the free plan.
func (s *Server) NewOwner() Owner {
	s.t.Helper()
	o := Owner{Email: dbtest.Unique("owner") + "@example.test", Password: "corr3ct-h0rse-battery-staple", Slug: dbtest.Unique("org")}
	var token string
	o.UserID, token, _ = s.SignUp(o.Email, o.Password)
	if _, err := dbtest.Pool(s.t).Exec(context.Background(), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1 AND organization_id IS NULL`, o.UserID); err != nil {
		s.t.Fatalf("apitest: verify the address: %v", err)
	}
	var out struct {
		session
		OrganizationID uuid.UUID `json:"organization_id"`
	}
	s.Do(http.MethodPost, "/v1/organizations", token, map[string]string{"slug": o.Slug, "name": "Test Organization", "plan": "free"}).
		Want(s.t, http.StatusCreated).JSON(s.t, &out)
	o.OrganizationID, o.Token, o.RefreshToken = out.OrganizationID, out.AccessToken, out.RefreshToken
	return o
}
