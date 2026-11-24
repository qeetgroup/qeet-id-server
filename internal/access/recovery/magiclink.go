package recovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// A magic link is a one-time emailed link that signs in the account holding the
// address. It opens, and is exchanged, only where it was asked for: the console
// or hosted login. Requests answer the same whether or not the address has an
// account, and are bounded per address and per caller.

// Where a magic link opens.
const (
	MagicLinkConsole     = "console"
	MagicLinkHostedLogin = AppHostedLogin
)

// MagicLinkRequest is a request for a sign-in link.
type MagicLinkRequest struct {
	Email          string    // the address to send the link to
	OrganizationID uuid.UUID // organization whose sign-in page asked; uuid.Nil for the console
	App            string    // MagicLinkHostedLogin, or anything else for the console
	ReturnTo       string    // hosted login only: where the journey continues, checked by the caller
	// Actor is the requester's address (for the per-caller bound), user agent
	// and request ID, for the audit record.
	audit.Actor
}

// Limiter bounds how often something may happen per key. Satisfied by
// *ratelimit.Limiter.
type Limiter interface {
	Take(ctx context.Context, key string) (bool, int)
}

func (s *Service) magicLinkAllowed(ctx context.Context, req MagicLinkRequest) bool {
	if ok, _ := s.magicPerAddress.Take(ctx, "magic-link:address:"+strings.ToLower(strings.TrimSpace(req.Email))); !ok {
		return false
	}
	if req.IP != "" {
		caller := req.IP
		if network := httpx.SourceNetwork(caller); network != "" {
			caller = network
		}
		if ok, _ := s.magicPerCaller.Take(ctx, "magic-link:caller:"+caller); !ok {
			return false
		}
	}
	return true
}

// RequestMagicLink emails a sign-in link to the account holding req.Email, if any, storing and sending
// it after it returns (afterAnswer) so it answers alike either way. ErrTooManyRequests past the
// bounds, ErrAuthMethodDisabled when the asking organization has magic links off, ErrAuthSSORequired
// for an SSO address. The account's own organization decides whether a link is sent and its lifetime.
func (s *Service) RequestMagicLink(ctx context.Context, req MagicLinkRequest) error {
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		return errs.ErrAuthEmailRequired
	}
	// An organization that has magic links off refuses before anything is
	// counted; its setting is no secret (its sign-in page omits the option).
	if req.OrganizationID != uuid.Nil {
		if _, err := s.magicLinkTTL(ctx, req.OrganizationID); err != nil {
			return err
		}
	}
	if !s.magicLinkAllowed(ctx, req) {
		return errs.ErrTooManyRequests
	}
	// Counted first, so asking about addresses on a captured domain is bounded
	// like any request; decided before the account is looked up.
	if err := s.refuseCaptured(ctx, req.Email); err != nil {
		return err
	}
	account, err := s.q.GetMagicLinkAccount(ctx, req.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing is sent; the caller answers as if it were
	}
	if err != nil {
		return err
	}
	s.afterAnswer(ctx, "send a magic link", func(ctx context.Context) error {
		return s.sendMagicLink(ctx, req, account)
	})
	return nil
}

// sendMagicLink stores and emails a link for account, requested by req. The
// asking organization brands the message and sees the request only when the
// account belongs to it; to anyone else's account it is the console's link.
func (s *Service) sendMagicLink(ctx context.Context, req MagicLinkRequest, account dbgen.GetMagicLinkAccountRow) error {
	home := postgres.ZeroIfNull(account.OrganizationID)
	ttl, err := s.magicLinkTTL(ctx, home)
	if errors.Is(err, errs.ErrAuthMethodDisabled) {
		return nil
	}
	if err != nil {
		return err
	}
	if req.OrganizationID != uuid.Nil {
		belongs, err := s.q.AccountBelongsTo(ctx, dbgen.AccountBelongsToParams{UserID: account.ID, OrganizationID: req.OrganizationID})
		if err != nil {
			return err
		}
		if !belongs {
			req.OrganizationID = uuid.Nil
		}
	}
	app := MagicLinkConsole
	if req.App == MagicLinkHostedLogin && s.loginBaseURL != "" {
		app = MagicLinkHostedLogin
	} else {
		req.ReturnTo = ""
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return err
	}
	var returnTo *string
	if req.ReturnTo != "" {
		returnTo = &req.ReturnTo
	}
	// The address as stored, not as typed: an address that only folds to the
	// account's under lower-casing belongs to someone else.
	if err := s.q.ExpireMagicLinks(ctx, account.Email); err != nil {
		return err
	}
	if err := s.q.InsertMagicLink(ctx, dbgen.InsertMagicLinkParams{
		OrganizationID: postgres.NullIfZero(req.OrganizationID),
		Email:          account.Email,
		TokenHash:      hash,
		ExpiresAt:      time.Now().UTC().Add(ttl),
		App:            app,
		ReturnTo:       returnTo,
	}); err != nil {
		return err
	}
	magicURL := s.magicLink(raw, app, req.ReturnTo)
	organization := ""
	if req.OrganizationID != uuid.Nil {
		organization = req.OrganizationID.String()
	}
	if err := s.sender.Send(ctx, notifier.Message{
		TemplateKey:       "magic_link",
		TemplateVariables: map[string]string{"magic_url": magicURL},
		OrganizationID:    organization,
		Channel:           "email",
		To:                account.Email,
		Subject:           "Your sign-in link",
		Body:              fmt.Sprintf("Sign in to Qeet ID: %s", magicURL),
		HTML: emailtmpl.Action(
			"Sign in to Qeet ID",
			"Click the button below to sign in. This link works once and expires shortly.",
			"Sign in", magicURL,
			"If you didn't ask for this link, you can safely ignore this email.",
		),
	}); err != nil {
		return err
	}
	s.recordRequest(ctx, "auth.magic_link_requested", account.ID, []uuid.UUID{home, req.OrganizationID}, req.Actor, map[string]any{"app": app})
	return nil
}

// magicLink is the emailed URL: the hosted login's magic page (with the
// journey's return_to, for its branding) or the console's.
func (s *Service) magicLink(raw, app, returnTo string) string {
	if app == MagicLinkHostedLogin {
		q := url.Values{}
		if returnTo != "" {
			q.Set("return_to", returnTo)
		}
		prefix := ""
		if len(q) > 0 {
			prefix = q.Encode() + "&"
		}
		return fmt.Sprintf("%s/magic-link?%stoken=%s", s.loginBaseURL, prefix, url.QueryEscape(raw))
	}
	return fmt.Sprintf("%s/magic?token=%s", s.baseAppURL, url.QueryEscape(raw))
}

// ResendMagicLink sends a new link in place of the one rawToken names —
// used, expired or not — to the same address, for the same place and
// journey, without the user typing the address again. It answers the same
// whatever the token names, and is bounded like any request.
func (s *Service) ResendMagicLink(ctx context.Context, rawToken string, from audit.Actor) error {
	row, err := s.q.GetMagicLinkByToken(ctx, codes.Hash(rawToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	req := MagicLinkRequest{Email: row.Email, App: row.App, Actor: from}
	if row.OrganizationID != nil {
		req.OrganizationID = *row.OrganizationID
	}
	if row.ReturnTo != nil {
		req.ReturnTo = *row.ReturnTo
	}
	return s.RequestMagicLink(ctx, req)
}

// MagicLinkResult is what consuming a magic link signs in.
type MagicLinkResult struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	// ReturnTo is where a hosted-login journey continues ("" for none).
	ReturnTo string
}

// ConsumeMagicLink exchanges a console link: it marks the link used and
// returns the account to sign in, with its own organization (uuid.Nil for
// none).
func (s *Service) ConsumeMagicLink(ctx context.Context, rawToken string, from audit.Actor) (*MagicLinkResult, error) {
	return s.consumeMagicLink(ctx, rawToken, MagicLinkConsole, from)
}

// ConsumeHostedMagicLink exchanges a hosted-login link, returning the account
// and where its journey continues.
func (s *Service) ConsumeHostedMagicLink(ctx context.Context, rawToken string, from audit.Actor) (*MagicLinkResult, error) {
	return s.consumeMagicLink(ctx, rawToken, MagicLinkHostedLogin, from)
}

func (s *Service) consumeMagicLink(ctx context.Context, rawToken, app string, from audit.Actor) (*MagicLinkResult, error) {
	hash := codes.Hash(rawToken)
	ml, account, err := magicLink(ctx, s.q, hash, app)
	if err != nil {
		return nil, err
	}
	// A link issued before the account's organization switched magic links off
	// stops working too; it stays unused. The policy is read before the
	// transaction, and the link checked again under lock inside it.
	if _, err := s.magicLinkTTL(ctx, postgres.ZeroIfNull(account.OrganizationID)); err != nil {
		return nil, err
	}
	// So does a link to an address whose organization now requires single
	// sign-on.
	if err := s.refuseCaptured(ctx, ml.Email); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	if ml, account, err = magicLink(ctx, qtx, hash, app); err != nil {
		return nil, err
	}
	if err := qtx.MarkMagicLinkUsed(ctx, ml.ID); err != nil {
		return nil, err
	}
	res := &MagicLinkResult{UserID: account.ID}
	var home *uuid.UUID
	if account.OrganizationID != nil {
		res.OrganizationID = *account.OrganizationID
		home = &res.OrganizationID
	}
	// The link proves the address as a reset does. Its first proof leaves
	// nothing set up before it, password included, and no session open.
	proved, err := proveAddress(ctx, tx, account.ID, home, "magic_link", false, from)
	if err != nil {
		return nil, err
	}
	if proved {
		if _, err := authentication.EndSignIns(ctx, tx, s.signals, account.ID, sessionsignal.ReasonAllSessionsRevoked); err != nil {
			return nil, err
		}
	}
	if ml.ReturnTo != nil {
		res.ReturnTo = *ml.ReturnTo
	}
	// Recorded for the account's organization, and for the one that asked,
	// which the link names only when the account belongs to it.
	by := as(from, "system", &account.ID)
	for _, org := range auditOrgs([]uuid.UUID{res.OrganizationID, postgres.ZeroIfNull(ml.OrganizationID)}) {
		if err := audit.Record(ctx, tx, by.EventIn(org, "auth.magic_link_consumed", "user", account.ID, map[string]any{"app": ml.App})); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// magicLink reads, through q, the link for app that hash names and the
// account it signs in to, refusing a link that is unknown, used or expired.
func magicLink(ctx context.Context, q *dbgen.Queries, hash, app string) (dbgen.GetMagicLinkByTokenRow, dbgen.GetMagicLinkAccountRow, error) {
	var account dbgen.GetMagicLinkAccountRow
	ml, err := q.GetMagicLinkByToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && ml.App != app) {
		return ml, account, ErrMagicLinkInvalid
	}
	if err != nil {
		return ml, account, err
	}
	if ml.UsedAt != nil {
		return ml, account, ErrLinkUsed
	}
	if time.Now().After(ml.ExpiresAt) {
		return ml, account, ErrLinkExpired
	}
	account, err = q.GetMagicLinkAccount(ctx, ml.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return ml, account, ErrMagicLinkInvalid
	}
	return ml, account, err
}
