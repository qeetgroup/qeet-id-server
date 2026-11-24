package oidc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// polledRequest is a device-code or backchannel request as the token endpoint
// reads it while its client polls. UserID is uuid.Nil until someone approves.
type polledRequest struct {
	ID              uuid.UUID
	ClientID        string
	OrganizationID  uuid.UUID
	UserID          uuid.UUID
	Scopes          []string
	Status          string
	IntervalSeconds int32
	LastPolledAt    *time.Time
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
}

// pollGrant is what sets a polled grant apart: the device grant (RFC 8628
// §3.4) or the backchannel one (OpenID CIBA §10.1). pollToken runs either.
type pollGrant struct {
	grantType    string // the grant the client must still be registered for
	param        string // the parameter carrying the code, as error descriptions name it
	flow         string // the flow's name in error descriptions
	confidential bool   // only a confidential client collects
	// addressPath names the address check the poller must pass, as a refusal
	// records it; "" for none, where the poller is the application's server.
	addressPath string
	// bindsGrant has the refresh token remember the code, so revoking the
	// request ends the grant it bought.
	bindsGrant bool
	lock       func(ctx context.Context, q *dbgen.Queries, hash string) (polledRequest, error)
	touch      func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error
	consume    func(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error
}

// pollToken answers a client polling with a device or backchannel request's code: slow_down sooner
// than the interval, authorization_pending, access_denied or expired_token until approved, then once
// the authorization-code tokens. One transaction spends the request, re-checks the person and stores
// the refresh token, so a refusal spends the code and a failure loses nothing. ip is the poller's.
func (s *Service) pollToken(ctx context.Context, g *pollGrant, clientID, clientSecret, rawCode, ip string) (*TokenResponse, error) {
	client, err := s.pollingClient(ctx, g, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if rawCode == "" {
		return nil, oauthErr("invalid_request", g.param+" required")
	}
	hash := codes.Hash(rawCode)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	req, refusal, err := s.approvedRequest(ctx, q, g, clientID, hash)
	if err == nil && refusal == nil {
		refusal, err = s.spendApproval(ctx, tx, q, g, req, ip)
	}
	if err != nil {
		return nil, err
	}
	// A refusal commits what the poll wrote (its time, the spent code, a
	// refusal's record) and answers it.
	if refusal != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, refusal
	}
	// The refresh token, decided as ExchangeCode decides it, is stored with
	// the spent code: a revocation can't slip between the two, and a failure
	// to store it leaves the code for the next poll. Neither flow takes a
	// resource indicator, so it binds none.
	refresh := ""
	if issuesRefreshToken(client.Scopes, client.GrantTypes, req.Scopes) {
		codeHash := ""
		if g.bindsGrant {
			codeHash = hash
		}
		refresh, err = s.issueRefreshToken(ctx, q, clientID, req.UserID, req.OrganizationID, req.Scopes, "", nil, codeHash, nil)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.polledTokens(ctx, clientID, req, refresh)
}

// pollingClient authenticates the polling client. A client no longer
// confidential where it must be, or no longer registered for the grant,
// redeems no approval it was given.
func (s *Service) pollingClient(ctx context.Context, g *pollGrant, clientID, clientSecret string) (authedClient, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return client, err
	}
	if g.confidential {
		if err := s.requireConfidential(ctx, client); err != nil {
			return client, err
		}
	}
	if !slices.Contains(client.GrantTypes, g.grantType) {
		return client, ErrGrantTypeNotAllowed
	}
	return client, nil
}

// approvedRequest locks the request the code hash names and times the poll.
// It returns the request once approved, or the refusal to commit (slowed,
// expired, pending, denied); err is a refusal that keeps nothing.
func (s *Service) approvedRequest(ctx context.Context, q *dbgen.Queries, g *pollGrant, clientID, hash string) (polledRequest, error, error) {
	req, err := g.lock(ctx, q, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return req, nil, oauthErr("invalid_grant", "unknown "+g.param)
	}
	if err != nil {
		return req, nil, err
	}
	// The code is bound to the client it was issued to.
	if req.ClientID != clientID {
		return req, nil, oauthErr("invalid_grant", "client mismatch")
	}
	if req.ConsumedAt != nil {
		return req, nil, oauthErr("invalid_grant", g.param+" already used")
	}

	// RFC 8628 §3.5: a poll sooner than the interval after the previous one
	// is slowed. Every poll is timed, a slowed one too, so the throttle runs
	// from the latest.
	now := time.Now()
	tooSoon := req.LastPolledAt != nil && now.Sub(*req.LastPolledAt) < time.Duration(req.IntervalSeconds)*time.Second
	if err := g.touch(ctx, q, req.ID); err != nil {
		return req, nil, err
	}
	if tooSoon {
		return req, oauthErr("slow_down", "polling too frequently"), nil
	}
	// Expiry takes precedence over a still-pending status.
	if now.After(req.ExpiresAt) {
		return req, oauthErr("expired_token", g.param+" expired"), nil
	}
	switch req.Status {
	case "pending":
		return req, oauthErr("authorization_pending", "the user has not yet completed authorization"), nil
	case "denied":
		return req, oauthErr("access_denied", "the user denied the authorization request"), nil
	case "authorized":
		// collected by the caller
	default:
		return req, nil, oauthErr("invalid_grant", "invalid "+g.flow+" authorization state")
	}
	if req.UserID == uuid.Nil {
		return req, nil, oauthErr("invalid_grant", g.flow+" authorization has no bound user")
	}
	return req, nil, nil
}

// spendApproval spends the approved request req, then re-checks the person
// it binds, and the poller's address ip where the grant asks: it returns the
// refusal to commit when one fails.
func (s *Service) spendApproval(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, g *pollGrant, req polledRequest, ip string) (error, error) {
	// One-time: spent now, so a second poll can't mint again, and a refusal
	// below spends it too.
	if err := g.consume(ctx, q, req.ID); err != nil {
		return nil, err
	}
	// An approval given before the account was suspended or deleted, or before
	// its person left the application's organization, issues nothing.
	active, err := accountActive(ctx, q, req.UserID)
	if err != nil {
		return nil, err
	}
	if !active {
		return oauthErr("invalid_grant", "account_suspended"), nil
	}
	member, err := s.activeOrganizationPrincipal(ctx, q, req.UserID, req.OrganizationID)
	if err != nil {
		return nil, err
	}
	if !member {
		return ErrUserOrganizationMismatch, nil
	}
	// A poller on an address the organization doesn't allow gets nothing, and
	// the flow starts again from an allowed one. The refusal is recorded in tx.
	if g.addressPath != "" {
		if err := s.checkAddressTx(ctx, tx, req.OrganizationID, req.UserID, ip, g.addressPath); err != nil {
			if !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
				return nil, err
			}
			return oauthErr("access_denied", "address_not_allowed"), nil
		}
	}
	return nil, nil
}

// polledTokens mints the access token, and the ID token when req asked for
// openid, of a collected request, with its refresh token.
func (s *Service) polledTokens(ctx context.Context, clientID string, req polledRequest, refresh string) (*TokenResponse, error) {
	scope := strings.Join(req.Scopes, " ")
	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: req.UserID, OrganizationID: req.OrganizationID, Scopes: scope, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if slices.Contains(req.Scopes, "openid") {
		idTok, err = s.signIDToken(ctx, idToken{UserID: req.UserID, OrganizationID: req.OrganizationID, Audience: clientID, Scopes: req.Scopes})
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
		Scope:        scope,
	}, nil
}
