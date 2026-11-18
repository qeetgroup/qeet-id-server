package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// OAuth 2.0 Device Authorization Grant (RFC 8628) for clients that can't open a
// browser (CLI, TV, IoT): the device shows a user_code and polls the token
// endpoint while the user approves on another device.

const (
	deviceCodeTTL      = 10 * time.Minute       // how long a device_code/user_code pair stays valid
	devicePollInterval = 5                      // minimum seconds between polls (RFC 8628 §3.2)
	userCodeAlphabet   = "BCDFGHJKLMNPQRSTVWXZ" // no ambiguous characters (RFC 8628 §6.1)
	userCodeGroup      = 4                      // characters per group, as in "XXXX-XXXX"
	userCodeGroups     = 2                      // groups per user code
)

// grantTypeDeviceCode is the RFC 8628 grant_type.
const grantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// oauthError is an RFC 6749 §5.2 / RFC 8628 §3.5 token-endpoint error. Unlike
// the canonical errs.Error envelope, the OAuth token endpoint must answer with
// the flat {"error", "error_description"} JSON shape that OAuth clients parse,
// so the grants return this and writeOAuthError renders it.
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

// writeOAuthError renders an RFC 6749 §5.2 error body: 401 for invalid_client,
// 400 for every other code, the device grant's polling errors
// (authorization_pending, slow_down, access_denied, expired_token) included.
func writeOAuthError(w http.ResponseWriter, e *oauthError) {
	body := map[string]string{"error": e.Code}
	if e.Description != "" {
		body["error_description"] = e.Description
	}
	status := http.StatusBadRequest
	if e.Code == "invalid_client" {
		status = http.StatusUnauthorized
	}
	httpx.WriteJSON(w, status, body)
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
// pair, persisting the row scoped to the client's organization. The device_code is
// stored hashed; the user_code is stored in the clear for the verification
// lookup. Returns the raw device_code + user_code for the response only.
func (s *Service) DeviceAuthorize(ctx context.Context, clientID string, scopes []string) (rawDeviceCode, userCode string, organizationID uuid.UUID, err error) {
	info, err := s.q.GetClientOrganizationAndScopes(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", uuid.Nil, ErrClientUnknown
	}
	if err != nil {
		return "", "", uuid.Nil, err
	}
	if !slices.Contains(info.GrantTypes, grantTypeDeviceCode) {
		return "", "", uuid.Nil, oauthErr("unauthorized_client", "client is not permitted the device grant")
	}
	organizationID = info.OrganizationID
	dbScopes := info.Scopes
	// An empty scope request defaults to the client's full registered set.
	if len(scopes) == 0 {
		scopes = dbScopes
	}
	for _, sc := range scopes {
		if !scopePermitted(dbScopes, info.GrantTypes, sc) {
			return "", "", uuid.Nil, ErrScopeNotPermitted
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
		err = s.q.InsertDeviceCode(ctx, dbgen.InsertDeviceCodeParams{
			DeviceCodeHash:  hash,
			UserCode:        userCode,
			ClientID:        clientID,
			OrganizationID:  organizationID,
			Scopes:          scopes,
			IntervalSeconds: int32(devicePollInterval),
		})
		if err == nil {
			return raw, userCode, organizationID, nil
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
	// OrganizationID is the organization of the application asking, whose
	// second-factor requirement the approval must meet; not shown.
	OrganizationID uuid.UUID `json:"-"`
}

// LookupDeviceByUserCode resolves a pending device-authorization row by its
// human-typed user_code, for the verification screen. It validates expiry and
// status (already-decided or expired codes are rejected).
func (s *Service) LookupDeviceByUserCode(ctx context.Context, userCode string) (*DeviceVerificationContext, error) {
	userCode = normalizeUserCode(userCode)
	row, err := s.q.GetDeviceByUserCode(ctx, userCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrUserCodeExpired
	}
	if row.Status != "pending" {
		return nil, ErrDeviceAlreadyDecided
	}
	name, _, err := s.ClientName(ctx, row.ClientID)
	if err != nil {
		return nil, err
	}
	return &DeviceVerificationContext{ClientName: name, Scopes: row.Scopes, OrganizationID: row.OrganizationID}, nil
}

// DecideDevice records the user's approve/deny decision against a pending device
// row identified by user_code. On approval it binds the user (who must belong to
// the row's organization, and approve from an address its rules allow: ip) and marks
// it authorized; on denial it marks it denied. Either is audited in the row's
// organization as oauth.device_approved or oauth.device_denied.
func (s *Service) DecideDevice(ctx context.Context, userID uuid.UUID, userCode string, approve bool, ip string) error {
	userCode = normalizeUserCode(userCode)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	row, err := q.LockDeviceByUserCode(ctx, userCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUserCodeInvalid
	}
	if err != nil {
		return err
	}
	if time.Now().After(row.ExpiresAt) {
		return ErrUserCodeExpired
	}
	if row.Status != "pending" {
		return ErrDeviceAlreadyDecided
	}

	if !approve {
		if err := q.DenyDevice(ctx, row.ID); err != nil {
			return err
		}
		if err := recordDeviceDecision(ctx, tx, row, userID, "oauth.device_denied", ip); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// The approving user must be an active member of the client's active
	// organization, as at a browser sign-in to the application.
	live, err := s.activeOrganizationPrincipal(ctx, q, userID, row.OrganizationID)
	if err != nil {
		return err
	}
	if !live {
		return ErrUserOrganizationMismatch
	}
	// Approving is the person's sign-in to the application. Nothing else is
	// written yet, so committing keeps only the refusal's record.
	if err := s.checkAddressTx(ctx, tx, row.OrganizationID, userID, ip, "device_approval"); err != nil {
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return cerr
			}
		}
		return err
	}

	// Record consent for the requested scopes so the grant is consistent with
	// the authorization_code flow (skips re-consent on later flows).
	if err := q.UpsertConsent(ctx, dbgen.UpsertConsentParams{
		UserID: userID, ClientID: row.ClientID, Scopes: row.Scopes,
	}); err != nil {
		return err
	}
	if err := q.ApproveDevice(ctx, dbgen.ApproveDeviceParams{
		UserID: &userID,
		ID:     row.ID,
	}); err != nil {
		return err
	}
	if err := recordDeviceDecision(ctx, tx, row, userID, "oauth.device_approved", ip); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordDeviceDecision audits userID's decision on device code row, made from
// ip, in the organization the code was issued for.
func recordDeviceDecision(ctx context.Context, tx pgx.Tx, row dbgen.LockDeviceByUserCodeRow, userID uuid.UUID, action, ip string) error {
	return audit.Record(ctx, tx, audit.Actor{UserID: &userID, Type: "user", IP: ip}.Event(row.OrganizationID, action, "oidc_device_code", row.ID,
		map[string]any{"client_id": row.ClientID, "scopes": row.Scopes}))
}

// deviceGrant is the device grant's polling (RFC 8628 §3.4). Its poller is
// the person's device, so its address must be one the organization allows,
// and its grant ends when the device authorization is revoked.
var deviceGrant = pollGrant{
	grantType:   grantTypeDeviceCode,
	param:       "device_code",
	flow:        "device",
	addressPath: "device",
	bindsGrant:  true,
	lock: func(ctx context.Context, q *dbgen.Queries, hash string) (polledRequest, error) {
		r, err := q.LockDeviceByCode(ctx, hash)
		return polledRequest{
			ID: r.ID, ClientID: r.ClientID, OrganizationID: r.OrganizationID, UserID: postgres.ZeroIfNull(r.UserID),
			Scopes: r.Scopes, Status: r.Status, IntervalSeconds: r.IntervalSeconds,
			LastPolledAt: r.LastPolledAt, ExpiresAt: r.ExpiresAt, ConsumedAt: r.ConsumedAt,
		}, err
	},
	touch:   func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error { return q.TouchDevicePollTime(ctx, id) },
	consume: func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error { return q.ConsumeDeviceCode(ctx, id) },
}

// DeviceToken implements the RFC 8628 §3.5 polling exchange (see pollToken).
// A confidential client authenticates as at the other grants; for a public
// one the device_code is the proof. ip is the device's address.
func (s *Service) DeviceToken(ctx context.Context, clientID, clientSecret, rawDeviceCode, ip string) (*TokenResponse, error) {
	return s.pollToken(ctx, &deviceGrant, clientID, clientSecret, rawDeviceCode, ip)
}

// normalizeUserCode upper-cases and strips spaces so a user can type the code
// loosely (e.g. lower-case, with a space instead of a dash variant). We keep the
// dash as the canonical separator the value was stored with.
func normalizeUserCode(in string) string {
	return strings.ToUpper(strings.TrimSpace(in))
}

// Admin device-authorization visibility (RFC 8628 rows): lets an organization admin see
// in-flight/recent device authorizations and revoke one. The device_code (and its
// hash) are NEVER exposed — only the human user_code and metadata. Organization-scoped.

// DeviceAuthorization is the admin-facing view of a device-authorization row.
// It deliberately omits device_code / device_code_hash.
// ConsumedAt is when the device redeemed an approval for tokens.
type DeviceAuthorization struct {
	ID           uuid.UUID  `json:"id"`
	ClientID     string     `json:"client_id"`
	ClientName   string     `json:"client_name"`
	UserCode     string     `json:"user_code"`
	Status       string     `json:"status"`
	UserID       *uuid.UUID `json:"user_id"`
	UserEmail    string     `json:"user_email"`
	Scopes       []string   `json:"scopes"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastPolledAt *time.Time `json:"last_polled_at"`
	ConsumedAt   *time.Time `json:"consumed_at"`
}

// ListDevices returns the organization's device-authorization rows, newest first.
func (s *Service) ListDevices(ctx context.Context, organizationID uuid.UUID) ([]DeviceAuthorization, error) {
	rows, err := s.q.ListDevices(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceAuthorization, len(rows))
	for i, r := range rows {
		out[i] = DeviceAuthorization{
			ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, UserCode: r.UserCode, Status: r.Status,
			UserID: r.UserID, UserEmail: r.UserEmail, Scopes: r.Scopes,
			CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
			LastPolledAt: r.LastPolledAt, ConsumedAt: r.ConsumedAt,
		}
	}
	return out, nil
}

// RevokeDevice marks an organization's device authorization denied, so any in-flight
// or future token poll fails, and ends the grant an approved one was redeemed
// for. Access tokens already issued run out on their own. ('denied' is the
// terminal revoked state.) Recorded as actor's. Organization-scoped.
func (s *Service) RevokeDevice(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.RevokeDevice(ctx, dbgen.RevokeDeviceParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDeviceNotFound
	}
	if err != nil {
		return err
	}
	ended, err := q.RevokeDeviceGrant(ctx, dbgen.RevokeDeviceGrantParams{
		OrganizationID: organizationID, ClientID: row.ClientID, DeviceCodeHash: &row.DeviceCodeHash,
	})
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "oauth.device_revoked", "oidc_device_code", id,
		map[string]any{"client_id": row.ClientID, "user_code": row.UserCode, "grant_ended": ended > 0})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListDevices(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokeDevice(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deviceAuthorization is the RFC 8628 §3.1 device-authorization endpoint:
// POST /oauth/device_authorization. It is client-authenticated like the token
// endpoint (form/Basic), CSRF-exempt in the router, and returns the
// (device_code, user_code) pair plus the verification URIs.
func (h *Handler) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if _, err := h.Service.authenticateClient(r.Context(), clientID, clientSecret); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if r.Form.Get("resource") != "" {
		// Explicitly refused, never silently dropped: this flow binds no resource.
		writeOAuthError(w, oauthErr("invalid_target", "resource indicators aren't supported on the device and backchannel flows"))
		return
	}
	scopes := strings.Fields(r.Form.Get("scope"))
	rawDeviceCode, userCode, _, err := h.Service.DeviceAuthorize(r.Context(), clientID, scopes)
	var oe *oauthError
	if errors.As(err, &oe) {
		writeOAuthError(w, oe)
		return
	}
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
		httpx.WriteError(w, r, ErrUserCodeRequired)
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
	loginSessionID, userID, ok := h.loginSession(r)
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
		httpx.WriteError(w, r, ErrUserCodeRequired)
		return
	}
	// Approving hands the device tokens for the application's organization,
	// so its second-factor requirement applies; denying needs none.
	if in.Approve {
		dc, err := h.Service.LookupDeviceByUserCode(r.Context(), in.UserCode)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := h.Sessions.LoginSessionFactorShortfall(r.Context(), loginSessionID, userID, dc.OrganizationID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := h.Service.DecideDevice(r.Context(), userID, in.UserCode, in.Approve, httpx.ClientIP(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	status := "denied"
	if in.Approve {
		status = "authorized"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status})
}
