package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// OpenID Connect CIBA (Client-Initiated Backchannel Authentication), poll mode
// only: a client that already knows the user (login_hint) starts a backchannel
// request; the user approves/denies out-of-band while the client polls with
// auth_req_id. The backchannel counterpart of the device grant (device.go) —
// same mechanics, but the user is known up front rather than via a typed code.

const (
	grantTypeCIBA = "urn:openid:params:grant-type:ciba"
	// cibaRequestTTL bounds how long a backchannel auth request stays pending.
	cibaRequestTTL = 10 * time.Minute
	// cibaPollInterval mirrors the device grant's poll throttle.
	cibaPollInterval = 5
)

// Notifier delivers an async, out-of-band prompt to a user (e.g. the in-app
// notification inbox). Optional — nil means no notification is sent and the
// user must know to check the pending-requests list themselves. Kept as an
// interface so oidc doesn't depend on the notifications package directly.
type Notifier interface {
	Notify(ctx context.Context, tenantID, userID uuid.UUID, kind, title, description, href string) error
}

// SetNotifier wires the CIBA consent-prompt notifier. Called from cmd/server/main.go.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// CIBAAuthResponse is the OpenID CIBA §7 backchannel-authentication response.
type CIBAAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BackchannelAuthorize resolves loginHint (an email, scoped to the client's
// own tenant) to a user, creates a pending CIBA request, and best-effort
// notifies that user. unknown_user_id and other failures use CIBA's own
// error vocabulary (OpenID CIBA §13) via oauthError, matching how the device
// grant's polling errors are rendered.
func (s *Service) BackchannelAuthorize(ctx context.Context, clientID, clientSecret, loginHint, scope, bindingMessage string) (*CIBAAuthResponse, error) {
	grantTypes, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(grantTypes, grantTypeCIBA) {
		return nil, oauthErr("unauthorized_client", "client is not permitted the CIBA grant")
	}
	if strings.TrimSpace(loginHint) == "" {
		return nil, oauthErr("invalid_request", "login_hint is required")
	}

	cinfo, err := s.q.GetClientTenantAndScopes(ctx, clientID)
	if err != nil {
		return nil, err
	}
	tenantID := cinfo.TenantID
	dbScopes := cinfo.Scopes
	scopes := strings.Fields(scope)
	if len(scopes) == 0 {
		scopes = dbScopes
	}
	for _, sc := range scopes {
		if !contains(dbScopes, sc) {
			return nil, oauthErr("invalid_scope", "scope not permitted: "+sc)
		}
	}

	userID, err := s.q.GetUserByEmailInTenant(ctx, dbgen.GetUserByEmailInTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Email:    loginHint,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("unknown_user_id", "login_hint does not resolve to a known user")
	}
	if err != nil {
		return nil, err
	}

	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	var msgArg *string
	if bindingMessage != "" {
		msgArg = &bindingMessage
	}
	if err := s.q.InsertCIBARequest(ctx, dbgen.InsertCIBARequestParams{
		AuthReqIDHash:   hash,
		ClientID:        clientID,
		TenantID:        tenantID,
		UserID:          userID,
		Scopes:          scopes,
		BindingMessage:  msgArg,
		IntervalSeconds: int32(cibaPollInterval),
	}); err != nil {
		return nil, err
	}

	if s.notifier != nil {
		name, _, nerr := s.ClientName(ctx, clientID)
		if nerr == nil {
			title := name + " is requesting access"
			desc := "Approve or deny this request from your account."
			if bindingMessage != "" {
				desc = bindingMessage
			}
			_ = s.notifier.Notify(ctx, tenantID, userID, "info", title, desc, "/account/sign-in-requests")
		}
	}

	return &CIBAAuthResponse{AuthReqID: raw, ExpiresIn: int(cibaRequestTTL.Seconds()), Interval: cibaPollInterval}, nil
}

// CIBAPendingRequest is what a user's "pending sign-in requests" view shows.
type CIBAPendingRequest struct {
	ID             uuid.UUID `json:"id"`
	ClientName     string    `json:"client_name"`
	Scopes         []string  `json:"scopes"`
	BindingMessage *string   `json:"binding_message,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// ListPendingCIBA returns userID's still-pending, unexpired CIBA requests.
func (s *Service) ListPendingCIBA(ctx context.Context, userID uuid.UUID) ([]CIBAPendingRequest, error) {
	rows, err := s.q.ListPendingCIBA(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]CIBAPendingRequest, len(rows))
	for i, r := range rows {
		name, _, _ := s.ClientName(ctx, r.ClientID)
		out[i] = CIBAPendingRequest{
			ID: r.ID, ClientName: name, Scopes: r.Scopes,
			BindingMessage: r.BindingMessage,
			CreatedAt:      r.CreatedAt, ExpiresAt: r.ExpiresAt,
		}
	}
	return out, nil
}

// DecideBackchannel records userID's approve/deny of one of their own
// pending CIBA requests (identified by its opaque id, not the raw
// auth_req_id — the id is what ListPendingCIBA shows). Unlike the device
// grant, the approving user is fixed by the request itself (it was resolved
// from login_hint at BackchannelAuthorize time), so this rejects any id that
// isn't userID's own.
func (s *Service) DecideBackchannel(ctx context.Context, userID, id uuid.UUID, approve bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	row, err := q.LockCIBARequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.UserID != userID {
		return errs.ErrForbidden.WithDetail("not your sign-in request")
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrBadRequest.WithDetail("request expired")
	}
	if row.Status != "pending" {
		return errs.ErrConflict.WithDetail("request already decided")
	}

	if !approve {
		if err := q.DenyCIBARequest(ctx, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := q.ApproveCIBARequest(ctx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// BackchannelToken implements the CIBA §10 token-polling exchange for
// grant_type=urn:openid:params:grant-type:ciba. Mirrors DeviceToken's
// pending/denied/expired/slow_down handling and one-time consumption.
func (s *Service) BackchannelToken(ctx context.Context, clientID, rawAuthReqID string) (*TokenResponse, error) {
	if rawAuthReqID == "" {
		return nil, oauthErr("invalid_request", "auth_req_id required")
	}
	hash := codes.Hash(rawAuthReqID)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	cr, err := q.LockCIBARequestByHash(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("invalid_grant", "unknown auth_req_id")
	}
	if err != nil {
		return nil, err
	}
	if cr.ClientID != clientID {
		return nil, oauthErr("invalid_grant", "client mismatch")
	}
	if cr.ConsumedAt.Valid {
		return nil, oauthErr("invalid_grant", "auth_req_id already used")
	}

	now := time.Now()
	if cr.LastPolledAt.Valid && now.Sub(cr.LastPolledAt.Time) < time.Duration(cr.IntervalSeconds)*time.Second {
		if err := q.TouchCIBAPollTime(ctx, cr.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("slow_down", "polling too frequently")
	}
	if err := q.TouchCIBAPollTime(ctx, cr.ID); err != nil {
		return nil, err
	}

	if now.After(cr.ExpiresAt) {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, oauthErr("expired_token", "auth_req_id expired")
	}

	switch cr.Status {
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
		return nil, oauthErr("invalid_grant", "invalid backchannel authorization state")
	}

	if err := q.ConsumeCIBARequest(ctx, cr.ID); err != nil {
		return nil, err
	}
	grantTypes, err := q.GetClientGrantTypes(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	userID := cr.UserID
	tenantID := cr.TenantID
	scopes := cr.Scopes
	access, _, err := s.issuer.IssueAccess(userID, tenantID, uuid.New(), strings.Join(scopes, " "))
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(userID, tenantID, clientID, "")
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	refresh := ""
	if contains(grantTypes, "refresh_token") {
		refresh, err = s.issueRefreshToken(ctx, clientID, userID, tenantID, scopes, "")
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

func (h *Handler) backchannelAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	resp, err := h.Service.BackchannelAuthorize(r.Context(), clientID, clientSecret,
		r.Form.Get("login_hint"), r.Form.Get("scope"), r.Form.Get("binding_message"))
	if err != nil {
		var oe *oauthError
		if errors.As(err, &oe) {
			writeOAuthError(w, oe)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// pendingBackchannel (GET /oauth/bc-authorize/pending) lists the
// authenticated user's own pending CIBA requests, for an "approve sign-in"
// view in the app.
func (h *Handler) pendingBackchannel(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListPendingCIBA(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type backchannelDecisionInput struct {
	ID      uuid.UUID `json:"id"`
	Approve bool      `json:"approve"`
}

// backchannelDecision (POST /oauth/bc-authorize/decision) records the
// authenticated user's approve/deny of one of their own pending requests.
func (h *Handler) backchannelDecision(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in backchannelDecisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DecideBackchannel(r.Context(), userID, in.ID, in.Approve); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	status := "denied"
	if in.Approve {
		status = "authorized"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status})
}
