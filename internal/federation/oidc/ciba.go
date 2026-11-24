package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// OpenID Connect CIBA (Client-Initiated Backchannel Authentication), poll mode
// only: a client that knows the user (login_hint) starts a request, the user
// approves out of band, and the client polls with auth_req_id.

const (
	grantTypeCIBA    = "urn:openid:params:grant-type:ciba" // the CIBA grant_type
	cibaRequestTTL   = 10 * time.Minute                    // how long a request stays pending
	cibaPollInterval = 5                                   // seconds between polls, as for the device grant
)

// CIBAAuthResponse is the OpenID CIBA §7 backchannel-authentication response.
type CIBAAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BackchannelAuthorize resolves loginHint (an email in the client's organization) to a
// user, creates a pending CIBA request and notifies the user. Errors use CIBA's
// own codes (OpenID CIBA §13).
func (s *Service) BackchannelAuthorize(ctx context.Context, clientID, clientSecret, loginHint, scope, bindingMessage string) (*CIBAAuthResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	if !slices.Contains(client.GrantTypes, grantTypeCIBA) {
		return nil, oauthErr("unauthorized_client", "client is not permitted the CIBA grant")
	}
	if strings.TrimSpace(loginHint) == "" {
		return nil, oauthErr("invalid_request", "login_hint is required")
	}

	cinfo, err := s.q.GetClientOrganizationAndScopes(ctx, clientID)
	if err != nil {
		return nil, err
	}
	organizationID := cinfo.OrganizationID
	dbScopes := cinfo.Scopes
	scopes := strings.Fields(scope)
	if len(scopes) == 0 {
		scopes = dbScopes
	}
	for _, sc := range scopes {
		if !scopePermitted(dbScopes, cinfo.GrantTypes, sc) {
			return nil, oauthErr("invalid_scope", "scope not permitted: "+sc)
		}
	}

	userID, err := s.q.GetUserByEmailInOrganization(ctx, dbgen.GetUserByEmailInOrganizationParams{
		OrganizationID: organizationID,
		Email:          loginHint,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("unknown_user_id", "login_hint does not resolve to a known user")
	}
	if err != nil {
		return nil, err
	}
	// GetUserByEmailInOrganization filters soft-deletes but not suspension, and the
	// organization's own state is never consulted. Match a browser sign-in's
	// requirement before minting anything.
	live, err := s.activeOrganizationPrincipal(ctx, s.q, userID, organizationID)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, oauthErr("unknown_user_id", "login_hint does not resolve to a known user")
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
		OrganizationID:  organizationID,
		UserID:          userID,
		Scopes:          scopes,
		BindingMessage:  msgArg,
		IntervalSeconds: int32(cibaPollInterval),
	}); err != nil {
		return nil, err
	}

	name, _, nerr := s.ClientName(ctx, clientID)
	if nerr == nil {
		title := name + " is requesting access"
		desc := "Approve or deny this request from your account."
		if bindingMessage != "" {
			desc = bindingMessage
		}
		// No console page lists pending requests, so the notice links nowhere.
		_ = s.notifier.Notify(ctx, organizationID, userID, "info", title, desc, "")
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

// DecideBackchannel records userID's approval or denial of one of their own
// pending CIBA requests, identified by its ID rather than auth_req_id, made
// through their session sessionID from ip. It rejects any request that isn't
// userID's.
func (s *Service) DecideBackchannel(ctx context.Context, userID, sessionID, id uuid.UUID, approve bool, ip string) error {
	// Approving is the person's sign-in to the application, so the session it
	// is made through must meet the second factor the request's organization
	// requires. That check reads the pool, so it comes before the transaction.
	if approve {
		organizationID, err := s.q.CIBARequestOrganization(ctx, dbgen.CIBARequestOrganizationParams{ID: id, UserID: userID})
		if err == nil {
			err = s.sessionFactors(ctx, sessionID, userID, organizationID)
		} else if errors.Is(err, pgx.ErrNoRows) {
			err = nil // refused below, as for any request that isn't theirs
		}
		if err != nil {
			return err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	row, err := q.LockCIBARequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCIBARequestNotFound
	}
	if err != nil {
		return err
	}
	if row.UserID != userID {
		return ErrCIBARequestNotOwned
	}
	if time.Now().After(row.ExpiresAt) {
		return ErrCIBARequestExpired
	}
	if row.Status != "pending" {
		return ErrCIBARequestAlreadyDecided
	}

	if !approve {
		if err := q.DenyCIBARequest(ctx, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	// As at device approval: an active member of the request's active
	// organization, from an address its rules allow. Nothing else is written
	// yet, so committing keeps only the refusal's record.
	live, err := s.activeOrganizationPrincipal(ctx, q, userID, row.OrganizationID)
	if err != nil {
		return err
	}
	if !live {
		return ErrUserOrganizationMismatch
	}
	if err := s.checkAddressTx(ctx, tx, row.OrganizationID, userID, ip, "ciba_approval"); err != nil {
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return cerr
			}
		}
		return err
	}
	if err := q.ApproveCIBARequest(ctx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// backchannelGrant is the CIBA grant's polling (OpenID CIBA §10.1), for a
// confidential client only. Its poller is the application's server, so the
// address rules were asked when the person approved.
var backchannelGrant = pollGrant{
	grantType:    grantTypeCIBA,
	param:        "auth_req_id",
	flow:         "backchannel",
	confidential: true,
	lock: func(ctx context.Context, q *dbgen.Queries, hash string) (polledRequest, error) {
		r, err := q.LockCIBARequestByHash(ctx, hash)
		return polledRequest{
			ID: r.ID, ClientID: r.ClientID, OrganizationID: r.OrganizationID, UserID: r.UserID,
			Scopes: r.Scopes, Status: r.Status, IntervalSeconds: r.IntervalSeconds,
			LastPolledAt: r.LastPolledAt, ExpiresAt: r.ExpiresAt, ConsumedAt: r.ConsumedAt,
		}, err
	},
	touch:   func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error { return q.TouchCIBAPollTime(ctx, id) },
	consume: func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error { return q.ConsumeCIBARequest(ctx, id) },
}

// BackchannelToken implements the CIBA §10 token-polling exchange for
// grant_type=urn:openid:params:grant-type:ciba (see pollToken).
func (s *Service) BackchannelToken(ctx context.Context, clientID, clientSecret, rawAuthReqID string) (*TokenResponse, error) {
	return s.pollToken(ctx, &backchannelGrant, clientID, clientSecret, rawAuthReqID, "")
}

func (h *Handler) backchannelAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if r.Form.Get("resource") != "" {
		// Explicitly refused, never silently dropped: this flow binds no resource.
		writeOAuthError(w, oauthErr("invalid_target", "resource indicators aren't supported on the device and backchannel flows"))
		return
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
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
	var sessionID uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.SessionID != nil {
		sessionID = *p.SessionID
	}
	if err := h.Service.DecideBackchannel(r.Context(), userID, sessionID, in.ID, in.Approve, httpx.ClientIP(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	status := "denied"
	if in.Approve {
		status = "authorized"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status})
}
