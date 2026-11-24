package tokenvault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault/dbgen"
)

// callbackURL is the vault's own fixed OAuth2 redirect target — never
// caller-supplied, so there's no open-redirect surface on the return leg.
func callbackURL(base string) string { return base + "/v1/vault/tokens/callback" }

// BeginConnect starts an authorization-code ceremony for (organizationID, userID)
// to connect provider, returning the URL to redirect the user's browser to
// and the ceremony's state, which the caller binds to that browser. The code
// redeems only with this ceremony's PKCE verifier.
func (s *Service) BeginConnect(ctx context.Context, organizationID, userID uuid.UUID, provider, base string) (string, string, error) {
	clientID, _, authorizeURL, _, scopes, err := s.providerConfig(ctx, organizationID, provider)
	if err != nil {
		return "", "", err
	}
	state, err := randomState()
	if err != nil {
		return "", "", err
	}
	verifier, err := randomState()
	if err != nil {
		return "", "", err
	}
	if err := s.q.InsertConnectState(ctx, dbgen.InsertConnectStateParams{
		State:          state,
		OrganizationID: organizationID,
		UserID:         userID,
		Provider:       provider,
		ExpiresAt:      time.Now().UTC().Add(connectStateTTL),
		CodeVerifier:   &verifier,
	}); err != nil {
		return "", "", err
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", "", ErrProviderAuthorizeInvalid
	}
	challenge := sha256.Sum256([]byte(verifier))
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", callbackURL(base))
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	if scopes != "" {
		q.Set("scope", scopes)
	}
	u.RawQuery = q.Encode()
	return u.String(), state, nil
}

// oauthTokenResponse is the standard OAuth 2.0 token response (RFC 6749 §5.1).
// ExpiresIn is any because some providers send it as a numeric string.
type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    any    `json:"expires_in"`
}

func (r oauthTokenResponse) expiresInSeconds() int64 {
	switch v := r.ExpiresIn.(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

// FinishConnect completes the ceremony: it validates the single-use state,
// exchanges code for tokens, encrypts them, and upserts the grant.
func (s *Service) FinishConnect(ctx context.Context, state, code, base string) error {
	cs, err := s.q.DeleteConnectState(ctx, state)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConnectStateInvalid
	}
	if err != nil {
		return err
	}
	organizationID, userID, provider := cs.OrganizationID, cs.UserID, cs.Provider
	if time.Now().After(cs.ExpiresAt) {
		return ErrConnectExpired
	}

	clientID, clientSecret, _, tokenURL, _, err := s.providerConfig(ctx, organizationID, provider)
	if err != nil {
		return err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL(base)},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if cs.CodeVerifier != "" {
		form.Set("code_verifier", cs.CodeVerifier)
	}
	tok, err := s.exchange(ctx, tokenURL, form)
	if err != nil {
		return err
	}
	return s.storeGrant(ctx, s.q, organizationID, userID, provider, tokenURL, clientID, tok)
}

// storeGrant encrypts and stores tok, which tokenURL issued to clientID,
// through q. It stores nothing, and refuses with ErrTokenVaultConnectStateInvalid,
// once the provider has another token URL or client.
func (s *Service) storeGrant(ctx context.Context, q *dbgen.Queries, organizationID, userID uuid.UUID, provider, tokenURL, clientID string, tok *oauthTokenResponse) error {
	accessCT, accessNonce, err := s.encrypt(organizationID, userID, provider, "token-vault-access", tok.AccessToken)
	if err != nil {
		return err
	}
	// nil []byte == SQL NULL for nullable bytea columns.
	var refreshCT, refreshNonce []byte
	if tok.RefreshToken != "" {
		ct, nonce, err := s.encrypt(organizationID, userID, provider, "token-vault-refresh", tok.RefreshToken)
		if err != nil {
			return err
		}
		refreshCT, refreshNonce = ct, nonce
	}
	var expiresAt *time.Time
	if secs := tok.expiresInSeconds(); secs > 0 {
		expiresAt = new(time.Now().UTC().Add(time.Duration(secs) * time.Second))
	}
	tokenType := tok.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	var scopeArg *string
	if tok.Scope != "" {
		scopeArg = &tok.Scope
	}
	n, err := q.UpsertTokenGrant(ctx, dbgen.UpsertTokenGrantParams{
		OrganizationID:    organizationID,
		UserID:            userID,
		Provider:          provider,
		AccessTokenCt:     accessCT,
		AccessTokenNonce:  accessNonce,
		RefreshTokenCt:    refreshCT,
		RefreshTokenNonce: refreshNonce,
		TokenType:         tokenType,
		Scope:             scopeArg,
		ExpiresAt:         expiresAt,
		TokenUrl:          tokenURL,
		ClientID:          clientID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConnectStateInvalid
	}
	return nil
}

// exchange POSTs a form-encoded OAuth2 token request and parses the response.
// Shared by the initial code exchange and refresh.
func (s *Service) exchange(ctx context.Context, tokenURL string, form url.Values) (*oauthTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode())) // #nosec G704 -- token URL checked by the egress policy on save
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req) // #nosec G704 -- egress-guarded client
	if err != nil {
		return nil, ErrTokenExchangeFailed.Wrap(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrTokenExchangeFailed
	}
	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, ErrTokenExchangeFailed.Wrap(err)
	}
	if tok.AccessToken == "" {
		return nil, ErrTokenExchangeFailed
	}
	return &tok, nil
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
