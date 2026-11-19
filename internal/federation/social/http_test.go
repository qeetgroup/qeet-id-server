package social

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSocialErrorsReachTheHostedLoginByName checks the code a failed social
// sign-in sends the hosted login with: a refusal the person can act on is
// named, among them a domain that requires single sign-on, however it was
// wrapped, and every other failure is only social, never the detail. The
// request's return_to goes with it.
func TestSocialErrorsReachTheHostedLoginByName(t *testing.T) {
	h := &Handler{LoginBaseURL: "https://login.example.test"}
	returnTo := "https://app.example.test/oauth/authorize?client_id=app"
	for _, c := range []struct {
		err  error
		want string
	}{
		{errs.ErrAuthSSORequired, "sso_required"},
		{errs.ErrAuthSSORequired.WithMetadata(map[string]any{"connections": []map[string]any{}}), "sso_required"},
		{errs.ErrAuthAccountInactive, "account_inactive"},
		{ErrAccountUnverified, "account_unverified"},
		{errs.ErrAuthSelfRegistrationDisabled, "registration_closed"},
		{ErrBrowserMismatch, "other_browser"},
		{ErrTokenExchangeFailed.Wrap(errors.New("upstream said no")), "social"},
		{errs.ErrUserDomainManaged, "social"},
		{errs.ErrInternalServer, "social"},
	} {
		err, want := c.err, c.want
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/social/corp/start?return_to="+url.QueryEscape(returnTo), nil)
		h.redirectSocialError(rec, req, err)
		u, perr := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || perr != nil || u.Host != "login.example.test" || u.Path != "/sign-in" {
			t.Fatalf("%v: %d %s; want a redirect to the hosted login", err, rec.Code, rec.Header().Get("Location"))
		}
		if q := u.Query(); q.Get("error") != want || q.Get("return_to") != returnTo || len(q) != 2 {
			t.Errorf("%v: hosted login given %v; want error=%s and the return_to, nothing else", err, q, want)
		}
	}
}

// TestSocialErrorWithoutAHostedLoginIsJSON checks that without a hosted login
// the refusal is answered as the JSON error, with its own status.
func TestSocialErrorWithoutAHostedLoginIsJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Handler{}).redirectToLogin(rec, httptest.NewRequest(http.MethodGet, "/social/corp/callback", nil), errs.ErrAuthSSORequired, "")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
		t.Errorf("no hosted login: %d %s; want the 403 itself", rec.Code, rec.Header().Get("Location"))
	}
}
