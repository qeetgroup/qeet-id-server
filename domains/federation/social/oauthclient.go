package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// discoveryDoc is the subset of an OIDC discovery document we consume.
type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// userInfo is the subset of OIDC userinfo claims we consume.
type userInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

type cachedDoc struct {
	doc       discoveryDoc
	expiresAt time.Time
}

const discoveryTTL = time.Hour

// oauthClient is a minimal generic OIDC relying-party client: it reads a
// provider's discovery document and drives the authorization-code exchange and
// userinfo lookup over plain net/http. Discovery docs are cached in-memory.
type oauthClient struct {
	http  *http.Client
	mu    sync.Mutex
	cache map[string]cachedDoc
}

func newOAuthClient() *oauthClient {
	return &oauthClient{
		http:  &http.Client{Timeout: 10 * time.Second},
		cache: map[string]cachedDoc{},
	}
}

// discovery fetches (and caches) a provider's OIDC discovery document.
func (c *oauthClient) discovery(ctx context.Context, discoveryURL string) (discoveryDoc, error) {
	c.mu.Lock()
	if hit, ok := c.cache[discoveryURL]; ok && time.Now().Before(hit.expiresAt) {
		c.mu.Unlock()
		return hit.doc, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDoc{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return discoveryDoc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discoveryDoc{}, fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return discoveryDoc{}, err
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return discoveryDoc{}, fmt.Errorf("discovery: missing endpoints")
	}
	c.mu.Lock()
	c.cache[discoveryURL] = cachedDoc{doc: doc, expiresAt: time.Now().Add(discoveryTTL)}
	c.mu.Unlock()
	return doc, nil
}

// exchange swaps an authorization code for an access token at the token endpoint.
func (c *oauthClient) exchange(ctx context.Context, doc discoveryDoc, clientID, clientSecret, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
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
		return "", fmt.Errorf("token endpoint: status %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: no access_token")
	}
	return tok.AccessToken, nil
}

// userinfo fetches the OIDC userinfo claims for an access token.
func (c *oauthClient) userinfo(ctx context.Context, doc discoveryDoc, accessToken string) (userInfo, error) {
	if doc.UserinfoEndpoint == "" {
		return userInfo{}, fmt.Errorf("provider has no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
	if err != nil {
		return userInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return userInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return userInfo{}, fmt.Errorf("userinfo: status %d", resp.StatusCode)
	}
	var ui userInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ui); err != nil {
		return userInfo{}, err
	}
	if ui.Subject == "" {
		return userInfo{}, fmt.Errorf("userinfo: no subject")
	}
	return ui, nil
}
