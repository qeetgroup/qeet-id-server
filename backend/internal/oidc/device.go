package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

// =====================================================================
// OAuth 2.0 Device Authorization Grant (RFC 8628)
//
// For input-constrained clients (CLI/TV/IoT) that can't open a browser
// locally. The device asks for a (device_code, user_code) pair, shows the
// user the user_code + a verification_uri, then polls the token endpoint
// with the device_code while the user approves the request on a second
// device (the hosted-login /device page → POST /oauth/device/decision,
// gated by the SSO cookie like authorize/decision).
// =====================================================================

const (
	// deviceCodeTTL is how long a (device_code, user_code) pair stays valid.
	deviceCodeTTL = 10 * time.Minute
	// devicePollInterval is the minimum number of seconds a device must wait
	// between polls (RFC 8628 §3.2 "interval"). Polling faster yields slow_down.
	devicePollInterval = 5
	// userCodeAlphabet excludes visually ambiguous characters (0/O, 1/I) so the
	// human-typed user_code is unambiguous (RFC 8628 §6.1).
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// userCodeGroup/userCodeGroups define the "XXXX-XXXX" shape (8 chars).
	userCodeGroup  = 4
	userCodeGroups = 2
)

// oauthError is an RFC 6749 §5.2 / RFC 8628 §3.5 token-endpoint error. Unlike
// the canonical errs.Error envelope, the OAuth token endpoint must answer with
// the flat {"error", "error_description"} JSON shape that OAuth clients parse,
// so the device-grant token branch returns this and writeOAuthError renders it.
type oauthError struct {
	Code        string
	Description string
}

func (e *oauthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

func oauthErr(code, desc string) *oauthError { return &oauthError{Code: code, Description: desc} }

// writeOAuthError renders an RFC 6749 §5.2 error body. All device-grant
// polling errors (authorization_pending, slow_down, access_denied,
// expired_token, invalid_grant, invalid_request) use HTTP 400 per the RFC.
func writeOAuthError(w http.ResponseWriter, e *oauthError) {
	body := map[string]string{"error": e.Code}
	if e.Description != "" {
		body["error_description"] = e.Description
	}
	httpx.WriteJSON(w, http.StatusBadRequest, body)
}

// DeviceAuthResponse is the RFC 8628 §3.2 device-authorization response.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// generateUserCode returns a human-friendly code like "BCDF-GHJK" drawn from an
// unambiguous alphabet (no 0/O/1/I).
func generateUserCode() (string, error) {
	groups := make([]string, userCodeGroups)
	max := big.NewInt(int64(len(userCodeAlphabet)))
	for g := 0; g < userCodeGroups; g++ {
		var b strings.Builder
		for i := 0; i < userCodeGroup; i++ {
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", err
			}
			b.WriteByte(userCodeAlphabet[n.Int64()])
		}
		groups[g] = b.String()
	}
	return strings.Join(groups, "-"), nil
}

// DeviceAuthorize validates the client and mints a (device_code, user_code)
// pair, persisting the row scoped to the client's tenant. The device_code is
// stored hashed; the user_code is stored in the clear for the verification
// lookup. Returns the raw device_code + user_code for the response only.
func (s *Service) DeviceAuthorize(ctx context.Context, clientID string, scopes []string) (rawDeviceCode, userCode string, tenantID uuid.UUID, err error) {
	var dbScopes []string
	err = s.pool.QueryRow(ctx, `
		SELECT tenant_id, scopes FROM auth.oidc_clients WHERE client_id = $1
	`, clientID).Scan(&tenantID, &dbScopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", uuid.Nil, errs.ErrBadRequest.WithDetail("unknown client")
	}
	if err != nil {
		return "", "", uuid.Nil, err
	}
	// An empty scope request defaults to the client's full registered set.
	if len(scopes) == 0 {
		scopes = dbScopes
	}
	for _, sc := range scopes {
		if !contains(dbScopes, sc) {
			return "", "", uuid.Nil, errs.ErrBadRequest.WithDetail("scope not permitted: " + sc)
		}
	}

	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", "", uuid.Nil, err
	}
	// user_code must be unique; retry on the rare collision.
	for attempt := 0; attempt < 5; attempt++ {
		userCode, err = generateUserCode()
		if err != nil {
			return "", "", uuid.Nil, err
		}
		_, err = s.pool.Exec(ctx, `
			INSERT INTO auth.oidc_device_codes (
				device_code_hash, user_code, client_id, tenant_id, scopes,
				interval_seconds, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '10 minutes')
		`, hash, userCode, clientID, tenantID, scopes, devicePollInterval)
		if err == nil {
			return raw, userCode, tenantID, nil
		}
		// 23505 = unique_violation; only the user_code can realistically collide.
		if !strings.Contains(err.Error(), "23505") {
			return "", "", uuid.Nil, err
		}
	}
	return "", "", uuid.Nil, err
}

// DeviceVerificationContext is what the hosted-login /device page renders: the
// requesting client's display name and the scopes it asked for.
type DeviceVerificationContext struct {
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
}

// LookupDeviceByUserCode resolves a pending device-authorization row by its
// human-typed user_code, for the verification screen. It validates expiry and
// status (already-decided or expired codes are rejected).
func (s *Service) LookupDeviceByUserCode(ctx context.Context, userCode string) (*DeviceVerificationContext, error) {
	userCode = normalizeUserCode(userCode)
	var (
		clientID  string
		scopes    []string
		status    string
		expiresAt time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, scopes, status, expires_at
		FROM auth.oidc_device_codes WHERE user_code = $1
	`, userCode).Scan(&clientID, &scopes, &status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound.WithDetail("unknown user_code")
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("user_code expired")
	}
	if status != "pending" {
		return nil, errs.ErrConflict.WithDetail("device authorization already decided")
	}
	name, _, err := s.ClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return &DeviceVerificationContext{ClientName: name, Scopes: scopes}, nil
}

// DecideDevice records the user's approve/deny decision against a pending device
// row identified by user_code. On approval it binds the user (who must belong to
// the row's tenant) and marks it authorized; on denial it marks it denied.
func (s *Service) DecideDevice(ctx context.Context, userID uuid.UUID, userCode string, approve bool) error {
	userCode = normalizeUserCode(userCode)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		id        uuid.UUID
		clientID  string
		tenantID  uuid.UUID
		scopes    []string
		status    string
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, client_id, tenant_id, scopes, status, expires_at
		FROM auth.oidc_device_codes WHERE user_code = $1
		FOR UPDATE
	`, userCode).Scan(&id, &clientID, &tenantID, &scopes, &status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound.WithDetail("unknown user_code")
	}
	if err != nil {
		return err
	}
	if time.Now().After(expiresAt) {
		return errs.ErrBadRequest.WithDetail("user_code expired")
	}
	if status != "pending" {
		return errs.ErrConflict.WithDetail("device authorization already decided")
	}

	if !approve {
		if _, err := tx.Exec(ctx,
			`UPDATE auth.oidc_device_codes SET status = 'denied' WHERE id = $1`, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// The approving user must belong to the client's tenant (multi-tenant).
	var ok bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM "user".users WHERE id = $1 AND tenant_id = $2)`,
		userID, tenantID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errs.ErrForbidden.WithDetail("user does not belong to the client's tenant")
	}

	// Record consent for the requested scopes so the grant is consistent with
	// the authorization_code flow (skips re-consent on later flows).
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.oidc_consents (user_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $3, granted_at = NOW()
	`, userID, clientID, scopes); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.oidc_device_codes
		SET status = 'authorized', user_id = $1, approved_at = NOW()
		WHERE id = $2
	`, userID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeviceToken implements the RFC 8628 §3.5 token-polling exchange for
// grant_type=urn:ietf:params:oauth:grant-type:device_code. It enforces the poll
// interval (slow_down) via last_polled_at, surfaces the pending/denied/expired
// states as RFC errors, and on success consumes the device_code one-time and
// issues the SAME token pair the authorization_code flow does.
func (s *Service) DeviceToken(ctx context.Context, clientID, rawDeviceCode string) (*TokenResponse, error) {
	if rawDeviceCode == "" {
		return nil, oauthErr("invalid_request", "device_code required")
	}
	hash := codes.Hash(rawDeviceCode)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id           uuid.UUID
		rowClientID  string
		tenantID     uuid.UUID
		userID       *uuid.UUID
		scopes       []string
		status       string
		intervalSecs int
		lastPolledAt *time.Time
		expiresAt    time.Time
		consumedAt   *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, client_id, tenant_id, user_id, scopes, status,
		       interval_seconds, last_polled_at, expires_at, consumed_at
		FROM auth.oidc_device_codes WHERE device_code_hash = $1
		FOR UPDATE
	`, hash).Scan(&id, &rowClientID, &tenantID, &userID, &scopes, &status,
		&intervalSecs, &lastPolledAt, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("invalid_grant", "unknown device_code")
	}
	if err != nil {
		return nil, err
	}
	// The device_code is bound to the client it was issued to.
	if rowClientID != clientID {
		return nil, oauthErr("invalid_grant", "client mismatch")
	}
	if consumedAt != nil {
		return nil, oauthErr("invalid_grant", "device_code already used")
	}

	now := time.Now()

	// Enforce the poll interval (RFC 8628 §3.5): a poll arriving sooner than
	// interval seconds after the previous one gets slow_down. We bump
	// last_polled_at on every poll (even slow_down) and commit so the throttle
	// reflects the most recent attempt.
	if lastPolledAt != nil && now.Sub(*lastPolledAt) < time.Duration(intervalSecs)*time.Second {
		if _, err := tx.Exec(ctx,
			`UPDATE auth.oidc_device_codes SET last_polled_at = NOW() WHERE id = $1`, id); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("slow_down", "polling too frequently")
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth.oidc_device_codes SET last_polled_at = NOW() WHERE id = $1`, id); err != nil {
		return nil, err
	}

	// Expiry takes precedence over a still-pending status.
	if now.After(expiresAt) {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("expired_token", "device_code expired")
	}

	switch status {
	case "pending":
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("authorization_pending", "the user has not yet completed authorization")
	case "denied":
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("access_denied", "the user denied the authorization request")
	case "authorized":
		// fall through to issue tokens.
	default:
		return nil, oauthErr("invalid_grant", "invalid device authorization state")
	}
	if userID == nil {
		return nil, oauthErr("invalid_grant", "device authorization has no bound user")
	}

	// One-time: consume the device_code so a second poll can't re-mint tokens.
	if _, err := tx.Exec(ctx,
		`UPDATE auth.oidc_device_codes SET consumed_at = NOW() WHERE id = $1`, id); err != nil {
		return nil, err
	}
	// The client's grant_types tell us whether to mint a refresh token, the same
	// way ExchangeCode does.
	var grantTypes []string
	if err := tx.QueryRow(ctx,
		`SELECT grant_types FROM auth.oidc_clients WHERE client_id = $1`, clientID).Scan(&grantTypes); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	access, _, err := s.issuer.IssueAccess(*userID, tenantID, uuid.New(), strings.Join(scopes, " "))
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(*userID, tenantID, clientID, "")
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	refresh := ""
	if contains(grantTypes, "refresh_token") {
		refresh, err = s.issueRefreshToken(ctx, clientID, *userID, tenantID, scopes)
		if err != nil {
			return nil, err
		}
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// normalizeUserCode upper-cases and strips spaces so a user can type the code
// loosely (e.g. lower-case, with a space instead of a dash variant). We keep the
// dash as the canonical separator the value was stored with.
func normalizeUserCode(in string) string {
	return strings.ToUpper(strings.TrimSpace(in))
}

// =====================================================================
// HTTP handlers
// =====================================================================

// deviceAuthorization is the RFC 8628 §3.1 device-authorization endpoint:
// POST /oauth/device_authorization. It is client-authenticated like the other
// token endpoints (form/Basic), CSRF-exempt in the router, and returns the
// (device_code, user_code) pair plus the verification URIs.
func (h *Handler) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	if _, err := h.Service.authenticateClient(r.Context(), clientID, clientSecret); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	scopes := strings.Fields(r.Form.Get("scope"))
	rawDeviceCode, userCode, _, err := h.Service.DeviceAuthorize(r.Context(), clientID, scopes)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	verifyURI := h.LoginBaseURL + "/device"
	httpx.WriteJSON(w, http.StatusOK, DeviceAuthResponse{
		DeviceCode:              rawDeviceCode,
		UserCode:                userCode,
		VerificationURI:         verifyURI,
		VerificationURIComplete: verifyURI + "?user_code=" + userCode,
		ExpiresIn:               int(deviceCodeTTL.Seconds()),
		Interval:                devicePollInterval,
	})
}

// deviceContext (GET /oauth/device?user_code=…) returns the client name +
// requested scopes for the hosted-login /device page to display before the user
// approves. SSO-cookie gated like the rest of the verification flow.
func (h *Handler) deviceContext(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionUser(r); !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_code required"))
		return
	}
	out, err := h.Service.LookupDeviceByUserCode(r.Context(), userCode)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type deviceDecisionInput struct {
	Approve  bool   `json:"approve"`
	UserCode string `json:"user_code"`
}

// deviceDecision (POST /oauth/device/decision) records the user's approve/deny
// of a device-authorization request. The user is identified by the SSO cookie,
// mirroring the authorize/decision consent handler.
func (h *Handler) deviceDecision(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.sessionUser(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in deviceDecisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.UserCode == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_code required"))
		return
	}
	if err := h.Service.DecideDevice(r.Context(), userID, in.UserCode, in.Approve); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	status := "denied"
	if in.Approve {
		status = "authorized"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status})
}
