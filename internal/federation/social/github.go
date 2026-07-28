package social

// GitHub OAuth adapter. Unlike Google/Microsoft, GitHub is not an OIDC provider
// (no discovery document, no userinfo endpoint, no PKCE for OAuth Apps), so it
// can't use the generic OIDC ceremony in oauthclient.go. This provides GitHub's
// authorize/token/user endpoints directly and maps the result onto the same
// userInfo shape the rest of the platform flow consumes.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
	githubScopes       = "read:user user:email"
)

// githubExchange swaps an authorization code for an access token. GitHub returns
// form-encoded by default; Accept: application/json makes it return JSON.
func (c *oauthClient) githubExchange(ctx context.Context, clientID, clientSecret, code, redirectURI string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github token endpoint: status %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("github token endpoint: no access_token (%s)", tok.Error)
	}
	return tok.AccessToken, nil
}

// githubUserinfo fetches the GitHub profile and maps it onto userInfo. The
// profile email is often null (private), so it falls back to the verified
// primary from /user/emails (requires the user:email scope).
func (c *oauthClient) githubUserinfo(ctx context.Context, accessToken string) (userInfo, error) {
	body, err := c.githubGet(ctx, githubUserURL, accessToken)
	if err != nil {
		return userInfo{}, err
	}
	var gh struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &gh); err != nil {
		return userInfo{}, err
	}
	if gh.ID == 0 {
		return userInfo{}, fmt.Errorf("github: no user id")
	}
	ui := userInfo{
		Subject: strconv.FormatInt(gh.ID, 10),
		Email:   gh.Email,
		Name:    gh.Name,
		Picture: gh.AvatarURL,
	}
	if ui.Name == "" {
		ui.Name = gh.Login
	}
	if ui.Email == "" {
		if ui.Email, err = c.githubPrimaryEmail(ctx, accessToken); err != nil {
			return userInfo{}, err
		}
	}
	return ui, nil
}

// githubPrimaryEmail returns the user's verified primary email (or any verified
// email) from /user/emails.
func (c *oauthClient) githubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	body, err := c.githubGet(ctx, githubEmailsURL, accessToken)
	if err != nil {
		return "", err
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}

// githubGet performs an authenticated GitHub API GET and returns the raw body.
// GitHub requires a User-Agent header, else it responds 403.
func (c *oauthClient) githubGet(ctx context.Context, endpoint, accessToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "qeet-id")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github %s: status %d", endpoint, resp.StatusCode)
	}
	return body, nil
}
