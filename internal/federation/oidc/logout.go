package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// When a hosted-login session ends, every application holding a code or grant
// from it is told: by a signed logout token POSTed to its backchannel_logout_uri,
// and by its frontchannel_logout_uri loaded on the signed-out page (OpenID
// Connect Back-Channel and Front-Channel Logout 1.0).

const (
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	logoutMaxAttempts      = 5
	logoutConfirmTTL       = 10 * time.Minute
)

// SetLogoutHTTPClient sets the outbound policy back-channel notices are sent
// under (the platform's SSRF guard).
func (s *Service) SetLogoutHTTPClient(p *egress.Policy) {
	s.logoutEgress = p
	s.logoutClient = p.HTTPClient(5 * time.Second)
}

// validLogoutURI is an absolute http(s) URL without a fragment ("" clears).
func validLogoutURI(raw string) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}

// NotifySignOut tells the applications in an ended hosted-login session. It
// queues a back-channel logout token for each, records who was told, and returns
// the front-channel addresses for the signed-out page. initiatedBy is the
// application that asked for the sign-out ("" for none).
func (s *Service) NotifySignOut(ctx context.Context, sessionID, userID uuid.UUID, initiatedBy string) ([]string, error) {
	clients, err := s.q.SessionClients(ctx, optionalUUID(sessionID))
	if err != nil || len(clients) == 0 {
		return nil, err
	}
	var frontchannel, backchannel []string
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	for _, c := range clients {
		if c.BackchannelLogoutUri != "" {
			token, err := s.logoutToken(c.ClientID, userID, sessionID)
			if err != nil {
				return nil, err
			}
			if err := q.InsertLogoutDelivery(ctx, dbgen.InsertLogoutDeliveryParams{
				TenantID: c.TenantID, ClientID: c.ClientID, Uri: c.BackchannelLogoutUri, LogoutToken: token,
			}); err != nil {
				return nil, err
			}
			backchannel = append(backchannel, c.ClientID)
		}
		if c.FrontchannelLogoutUri != "" {
			frontchannel = append(frontchannel, appendQuery(c.FrontchannelLogoutUri,
				"iss", s.issuer.JWTIssuer(), "sid", sessionID.String()))
		}
	}
	tenantID := clients[0].TenantID
	sid := sessionID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "user",
		Action: "oidc.sign_out_notified", ResourceType: "login_session", ResourceID: &sid,
		Metadata: map[string]any{
			"initiated_by": initiatedBy, "backchannel": backchannel, "frontchannel_clients": len(frontchannel),
		},
	}); err != nil {
		return nil, err
	}
	return frontchannel, tx.Commit(ctx)
}

// logoutToken is the signed notice a back-channel address receives.
func (s *Service) logoutToken(clientID string, userID, sessionID uuid.UUID) (string, error) {
	now := time.Now().UTC()
	return s.issuer.Sign(jwt.MapClaims{
		"iss":    s.issuer.JWTIssuer(),
		"aud":    clientID,
		"iat":    now.Unix(),
		"exp":    now.Add(2 * time.Minute).Unix(),
		"jti":    uuid.NewString(),
		"sub":    userID.String(),
		"sid":    sessionID.String(),
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	})
}

// RunLogoutDeliveries delivers queued back-channel notices every few seconds
// until ctx ends.
func (s *Service) RunLogoutDeliveries(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.DeliverLogoutNotices(ctx); err != nil {
				slog.Warn("oidc: deliver sign-out notices", "err", err)
			}
		}
	}
}

// DeliverLogoutNotices makes one delivery pass and returns how many notices
// it delivered. A failure is retried with backoff; after logoutMaxAttempts it
// stops and is recorded (oidc.backchannel_logout_failed) for admins.
func (s *Service) DeliverLogoutNotices(ctx context.Context) (int, error) {
	rows, err := s.q.ClaimLogoutDeliveries(ctx, 20)
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, d := range rows {
		if err := s.postLogoutToken(ctx, d.Uri, d.LogoutToken); err != nil {
			attempt := int(d.Attempts) + 1
			final := attempt >= logoutMaxAttempts
			if merr := s.q.MarkLogoutDeliveryFailed(ctx, dbgen.MarkLogoutDeliveryFailedParams{
				ID: d.ID, LastError: truncate(err.Error(), 300),
				RetryInSeconds: (time.Duration(1<<attempt) * 30 * time.Second).Seconds(), Final: final,
			}); merr != nil {
				return delivered, merr
			}
			if final {
				s.auditLogoutFailed(ctx, d.TenantID, d.ClientID, d.Uri, err)
			}
			continue
		}
		if err := s.q.MarkLogoutDelivered(ctx, d.ID); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}

func (s *Service) postLogoutToken(ctx context.Context, uri, token string) error {
	if s.logoutClient == nil {
		return errors.New("no outbound client configured")
	}
	if _, err := s.logoutEgress.ValidateHTTPURL(uri); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.logoutClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sign-out notice answered %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) auditLogoutFailed(ctx context.Context, tenantID uuid.UUID, clientID, uri string, cause error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "system", Action: "oidc.backchannel_logout_failed", ResourceType: "oidc_client",
		Metadata: map[string]any{"client_id": clientID, "uri": uri, "attempts": logoutMaxAttempts, "error": truncate(cause.Error(), 300)},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// logoutConfirmation is a short-lived ticket naming the hosted-login session a
// sign-out without id_token_hint was confirmed for: the hosted login asks the
// person, then comes back with it. Another site can't obtain one for a victim,
// so a plain link or image can't sign anyone out.
func (s *Service) logoutConfirmation(sessionID uuid.UUID) (string, error) {
	return s.issuer.Sign(jwt.MapClaims{
		"iss": s.issuer.JWTIssuer(), "typ": "logout_confirmation", "sid": sessionID.String(),
		"exp": time.Now().Add(logoutConfirmTTL).Unix(),
	})
}

// confirmedFor reports whether ticket confirms signing out of sessionID.
func (s *Service) confirmedFor(ticket string, sessionID uuid.UUID) bool {
	if ticket == "" {
		return false
	}
	claims, err := s.issuer.VerifyVC(ticket)
	if err != nil {
		return false
	}
	typ, _ := claims["typ"].(string)
	sid, _ := claims["sid"].(string)
	return typ == "logout_confirmation" && sid == sessionID.String()
}

// logoutContinuation signs the post-logout address a sign-out validated, for
// the hosted signed-out page to continue to through endSessionContinue.
func (s *Service) logoutContinuation(target string) (string, error) {
	return s.issuer.Sign(jwt.MapClaims{
		"iss": s.issuer.JWTIssuer(), "typ": "logout_continuation", "target": target,
		"exp": time.Now().Add(logoutConfirmTTL).Unix(),
	})
}

// continuationTarget is the address a continuation ticket signed, if valid.
func (s *Service) continuationTarget(ticket string) (string, bool) {
	if ticket == "" {
		return "", false
	}
	claims, err := s.issuer.VerifyVC(ticket)
	if err != nil {
		return "", false
	}
	typ, _ := claims["typ"].(string)
	target, _ := claims["target"].(string)
	return target, typ == "logout_continuation" && target != ""
}

// logoutHint is what a verified id_token_hint says about the sign-out.
type logoutHint struct {
	ClientID, Subject, SessionID string
}

// checkLogoutHint verifies an id_token_hint (one of our ID tokens, expired or
// not) and that it names this session and person, and the application asking.
func (s *Service) checkLogoutHint(raw, clientID string, sessionID, userID uuid.UUID) (*logoutHint, error) {
	claims, err := s.issuer.VerifySignedAnyTime(raw)
	if err != nil {
		return nil, oauthErr("invalid_request", "id_token_hint is not an ID token this server issued")
	}
	h := &logoutHint{}
	h.Subject, _ = claims["sub"].(string)
	h.SessionID, _ = claims["sid"].(string)
	switch aud := claims["aud"].(type) {
	case string:
		h.ClientID = aud
	case []any:
		if len(aud) > 0 {
			h.ClientID, _ = aud[0].(string)
		}
	}
	if clientID != "" && h.ClientID != clientID {
		return nil, oauthErr("invalid_request", "id_token_hint was issued to another application")
	}
	if sessionID != uuid.Nil {
		if (h.SessionID != "" && h.SessionID != sessionID.String()) || (h.Subject != "" && h.Subject != userID.String()) {
			return nil, oauthErr("invalid_request", "id_token_hint names another sign-in")
		}
	}
	return h, nil
}
