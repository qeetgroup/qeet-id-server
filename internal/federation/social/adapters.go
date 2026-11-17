package social

// An organization's provider named github, facebook, x, discord or apple isn't
// OpenID Connect: each has its own authorize, token and user calls, mapped onto
// the same userInfo. Any other name is an OpenID Connect provider found by its
// discovery document.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Provider kinds: OpenID Connect, or one of the OAuth 2.0 adapters.
const (
	kindOIDC     = "oidc"
	kindGitHub   = "github"
	kindFacebook = "facebook"
	kindX        = "x"
	kindDiscord  = "discord"
	kindApple    = "apple"
)

// adapterKind is the kind of provider named provider.
func adapterKind(provider string) string {
	switch provider {
	case kindGitHub, kindFacebook, kindX, kindDiscord, kindApple:
		return provider
	}
	return kindOIDC
}

// oauth2Endpoints are an OAuth 2.0 adapter's endpoints and scopes. pkce sends
// a S256 challenge, which X requires; basicAuth authenticates the client at
// the token endpoint with HTTP Basic, as X requires, instead of in the form.
type oauth2Endpoints struct {
	authorizeURL, tokenURL, userURL, scopes string
	pkce, basicAuth                         bool
}

// defaultEndpoints are the adapters' public endpoints.
var defaultEndpoints = map[string]oauth2Endpoints{
	kindFacebook: {
		authorizeURL: "https://www.facebook.com/v21.0/dialog/oauth",
		tokenURL:     "https://graph.facebook.com/v21.0/oauth/access_token", // #nosec G101 -- public endpoint URL
		userURL:      "https://graph.facebook.com/v21.0/me?fields=id,name,email,picture.type(large)",
		scopes:       "email public_profile",
	},
	kindX: {
		authorizeURL: "https://x.com/i/oauth2/authorize",
		tokenURL:     "https://api.x.com/2/oauth2/token", // #nosec G101 -- public endpoint URL
		userURL:      "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email",
		scopes:       "users.read tweet.read users.email",
		pkce:         true, basicAuth: true,
	},
	kindDiscord: {
		authorizeURL: "https://discord.com/oauth2/authorize",
		tokenURL:     "https://discord.com/api/oauth2/token", // #nosec G101 -- public endpoint URL
		userURL:      "https://discord.com/api/users/@me",
		scopes:       "identify email",
	},
}

// oauth2AuthorizeURL is where kind's authorize flow starts, for clientID back
// to redirectURI with state, and challenge when the adapter uses PKCE.
func (c *oauthClient) oauth2AuthorizeURL(kind, clientID, redirectURI, state, challenge string) string {
	ep := c.endpoints[kind]
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {ep.scopes},
		"state":         {state},
	}
	if ep.pkce {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	return ep.authorizeURL + "?" + q.Encode()
}

// oauth2Exchange swaps an authorization code for kind's access token.
func (c *oauthClient) oauth2Exchange(ctx context.Context, kind, clientID, clientSecret, code, redirectURI, verifier string) (string, error) {
	ep := c.endpoints[kind]
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if ep.pkce {
		form.Set("code_verifier", verifier)
	}
	if !ep.basicAuth {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if ep.basicAuth {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	body, err := c.do(req, kind+" token endpoint")
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("%s token endpoint: no access_token", kind)
	}
	return tok.AccessToken, nil
}

// oauth2Userinfo fetches kind's profile for accessToken and maps it onto
// userInfo. An address counts as verified only when the provider says so:
// X's confirmed_email and Discord's verified do; Facebook says nothing, so its
// address may name a new account but never adopts an existing one.
func (c *oauthClient) oauth2Userinfo(ctx context.Context, kind, accessToken string) (userInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoints[kind].userURL, nil)
	if err != nil {
		return userInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qeet-id")
	body, err := c.do(req, kind+" user endpoint")
	if err != nil {
		return userInfo{}, err
	}
	var ui userInfo
	switch kind {
	case kindFacebook:
		var fb struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Email   string `json:"email"`
			Picture struct {
				Data struct {
					URL string `json:"url"`
				} `json:"data"`
			} `json:"picture"`
		}
		if err := json.Unmarshal(body, &fb); err != nil {
			return userInfo{}, err
		}
		ui = userInfo{Subject: fb.ID, Name: fb.Name, Email: fb.Email, Picture: fb.Picture.Data.URL}
	case kindX:
		var x struct {
			Data struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				Username        string `json:"username"`
				ProfileImageURL string `json:"profile_image_url"`
				ConfirmedEmail  string `json:"confirmed_email"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return userInfo{}, err
		}
		ui = userInfo{Subject: x.Data.ID, Name: x.Data.Name, Email: x.Data.ConfirmedEmail, Picture: x.Data.ProfileImageURL,
			EmailVerified: x.Data.ConfirmedEmail != ""}
		if ui.Name == "" {
			ui.Name = x.Data.Username
		}
	case kindDiscord:
		var d struct {
			ID         string `json:"id"`
			Username   string `json:"username"`
			GlobalName string `json:"global_name"`
			Email      string `json:"email"`
			Verified   bool   `json:"verified"`
			Avatar     string `json:"avatar"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return userInfo{}, err
		}
		ui = userInfo{Subject: d.ID, Name: d.GlobalName, Email: d.Email, EmailVerified: d.Verified && d.Email != ""}
		if ui.Name == "" {
			ui.Name = d.Username
		}
		if d.Avatar != "" {
			ui.Picture = "https://cdn.discordapp.com/avatars/" + d.ID + "/" + d.Avatar + ".png"
		}
	default:
		return userInfo{}, fmt.Errorf("no OAuth 2.0 adapter for %q", kind)
	}
	if ui.Subject == "" {
		return userInfo{}, fmt.Errorf("%s: no user id", kind)
	}
	return ui, nil
}

// do sends req and returns the body of a 200 answer.
func (c *oauthClient) do(req *http.Request, what string) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", what, resp.StatusCode)
	}
	return body, nil
}

// errAppleKey refuses an Apple provider whose key can't sign a client secret.
var errAppleKey = errors.New("apple: the private key, team ID and key ID can't sign a client secret")
