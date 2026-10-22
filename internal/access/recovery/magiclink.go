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
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Magic links: a one-time link, emailed on request, that signs the account
// holding the address in. A link opens where it was asked for — the console
// (which exchanges it for tokens) or the hosted login (which opens a
// hosted-login session and continues the sign-in journey it came from) — and
// is exchanged only there. It lives as long as the organisation's
// magic_link_ttl_minutes and works once; its token is stored hashed.
//
// Asking for one answers the same whether or not the address has an account,
// and sends nothing when it has none. An organisation with magic links off
// refuses links asked for from its sign-in page; a console request for an
// account whose organisation has them off sends nothing. Requests are bounded
// per address and per caller (SetMagicLinkLimits), counted whether or not the
// address has an account, so the bound reveals nothing either.

// Where a magic link opens.
const (
	MagicLinkConsole     = "console"
	MagicLinkHostedLogin = AppHostedLogin
)

// MagicLinkRequest is a request for a sign-in link.
type MagicLinkRequest struct {
	Email string
	// TenantID is the organisation whose sign-in page asked (uuid.Nil: the
	// console's).
	TenantID uuid.UUID
	// App is where the link opens: MagicLinkHostedLogin, or anything else for
	// the console.
	App string
	// ReturnTo (hosted login only) is where the sign-in journey continues; the
	// caller has already kept it only if it is this service's authorize
	// endpoint.
	ReturnTo string
	// Caller identifies the requester for the per-caller bound (its IP).
	Caller string
	// UserAgent is the requester's, for the record of the request.
	UserAgent string
}

// Limiter bounds how often something may happen per key. Satisfied by
// *ratelimit.Limiter.
type Limiter interface {
	Take(ctx context.Context, key string) (bool, int)
}

// SetMagicLinkLimits bounds magic-link requests per address and per caller
// (nil: unbounded). Called from internal/bootstrap/dependencies.go.
func (s *Service) SetMagicLinkLimits(perAddress, perCaller Limiter) {
	s.magicPerAddress, s.magicPerCaller = perAddress, perCaller
}

func (s *Service) magicLinkAllowed(ctx context.Context, req MagicLinkRequest) bool {
	if s.magicPerAddress != nil {
		if ok, _ := s.magicPerAddress.Take(ctx, "magic-link:address:"+strings.ToLower(strings.TrimSpace(req.Email))); !ok {
			return false
		}
	}
	if s.magicPerCaller != nil && req.Caller != "" {
		if ok, _ := s.magicPerCaller.Take(ctx, "magic-link:caller:"+req.Caller); !ok {
			return false
		}
	}
	return true
}

// StartMagicLink emails a console sign-in link for email, asked for from
// tenantID's sign-in page (uuid.Nil: the console's own).
func (s *Service) StartMagicLink(ctx context.Context, tenantID uuid.UUID, email string) error {
	return s.RequestMagicLink(ctx, MagicLinkRequest{Email: email, TenantID: tenantID})
}

// RequestMagicLink emails a sign-in link to the account holding req.Email,
// if there is one; see the package notes for what is refused and when nothing
// is sent. ErrTooManyRequests past the bounds; ErrAuthMethodDisabled when the
// organisation that asked has magic links off.
func (s *Service) RequestMagicLink(ctx context.Context, req MagicLinkRequest) error {
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		return errs.ErrAuthEmailRequired
	}
	// An organisation that has magic links off refuses before anything is
	// counted; its setting is no secret (its sign-in page omits the option).
	var ttl time.Duration
	if req.TenantID != uuid.Nil {
		var err error
		if ttl, err = s.magicLinkTTL(ctx, req.TenantID); err != nil {
			return err
		}
	}
	if !s.magicLinkAllowed(ctx, req) {
		return errs.ErrTooManyRequests
	}
	account, err := s.q.GetMagicLinkAccount(ctx, req.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing is sent; the caller answers as if it were
	}
	if err != nil {
		return err
	}
	if req.TenantID == uuid.Nil {
		// From the console: the account's own organisation decides.
		if ttl, err = s.magicLinkTTL(ctx, uuid.UUID(account.TenantID.Bytes)); err != nil {
			if errors.Is(err, errs.ErrAuthMethodDisabled) {
				return nil
			}
			return err
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
	if err := s.q.InsertMagicLink(ctx, dbgen.InsertMagicLinkParams{
		TenantID:  pgtype.UUID{Bytes: req.TenantID, Valid: req.TenantID != uuid.Nil},
		Email:     req.Email,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(ttl),
		App:       app,
		ReturnTo:  returnTo,
	}); err != nil {
		return err
	}
	magicURL := s.magicLink(raw, app, req.ReturnTo)
	tenant := ""
	if req.TenantID != uuid.Nil {
		tenant = req.TenantID.String()
	}
	if err := s.sender.Send(ctx, notifier.Message{
		TemplateKey:       "magic_link",
		TemplateVariables: map[string]string{"magic_url": magicURL},
		TenantID:          tenant,
		Channel:           "email",
		To:                req.Email,
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
	// Recorded under the organisation that asked, or the account's own.
	org := req.TenantID
	if org == uuid.Nil && account.TenantID.Valid {
		org = account.TenantID.Bytes
	}
	var orgOf *uuid.UUID
	if org != uuid.Nil {
		orgOf = &org
	}
	s.recordRequest(ctx, "auth.magic_link_requested", account.ID, orgOf, AuditCtx{IP: req.Caller, UserAgent: req.UserAgent}, map[string]any{"app": app})
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
		return fmt.Sprintf("%s/magic?%stoken=%s", s.loginBaseURL, prefix, url.QueryEscape(raw))
	}
	return fmt.Sprintf("%s/magic?token=%s", s.baseAppURL, url.QueryEscape(raw))
}

// ResendMagicLink sends a new link in place of the one rawToken names —
// used, expired or not — to the same address, for the same place and
// journey, without the user typing the address again. It answers the same
// whatever the token names, and is bounded like any request.
func (s *Service) ResendMagicLink(ctx context.Context, rawToken, caller string) error {
	row, err := s.q.GetMagicLinkByToken(ctx, codes.Hash(rawToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	req := MagicLinkRequest{Email: row.Email, App: row.App, Caller: caller}
	if row.TenantID.Valid {
		req.TenantID = uuid.UUID(row.TenantID.Bytes)
	}
	if row.ReturnTo != nil {
		req.ReturnTo = *row.ReturnTo
	}
	return s.RequestMagicLink(ctx, req)
}

type MagicLinkResult struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	// ReturnTo is where a hosted-login journey continues ("" for none).
	ReturnTo string
}

// ConsumeMagicLink exchanges a console link: it marks the link used and
// returns the account to sign in, with its own organisation (uuid.Nil for
// none).
func (s *Service) ConsumeMagicLink(ctx context.Context, rawToken string, ac AuditCtx) (*MagicLinkResult, error) {
	return s.consumeMagicLink(ctx, rawToken, MagicLinkConsole, ac)
}

// ConsumeHostedMagicLink exchanges a hosted-login link, returning the account
// and where its journey continues.
func (s *Service) ConsumeHostedMagicLink(ctx context.Context, rawToken string, ac AuditCtx) (*MagicLinkResult, error) {
	return s.consumeMagicLink(ctx, rawToken, MagicLinkHostedLogin, ac)
}

func (s *Service) consumeMagicLink(ctx context.Context, rawToken, app string, ac AuditCtx) (*MagicLinkResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	ml, err := qtx.GetMagicLinkByToken(ctx, codes.Hash(rawToken))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && ml.App != app) {
		return nil, errs.ErrMagicLinkInvalid
	}
	if err != nil {
		return nil, err
	}
	if ml.UsedAt.Valid {
		return nil, errs.ErrRecoveryLinkUsed
	}
	if time.Now().After(ml.ExpiresAt) {
		return nil, errs.ErrRecoveryLinkExpired
	}
	account, err := qtx.GetMagicLinkAccount(ctx, ml.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrMagicLinkInvalid
	}
	if err != nil {
		return nil, err
	}
	// A link issued before its organisation switched magic links off stops
	// working too; it stays unused. A console link answers to the account's
	// own organisation.
	policyTenant := uuid.UUID(ml.TenantID.Bytes)
	if !ml.TenantID.Valid {
		policyTenant = uuid.UUID(account.TenantID.Bytes)
	}
	if _, err := s.magicLinkTTL(ctx, policyTenant); err != nil {
		return nil, err
	}
	if err := qtx.MarkMagicLinkUsed(ctx, ml.ID); err != nil {
		return nil, err
	}
	res := &MagicLinkResult{UserID: account.ID}
	if account.TenantID.Valid {
		res.TenantID = uuid.UUID(account.TenantID.Bytes)
	}
	if ml.ReturnTo != nil {
		res.ReturnTo = *ml.ReturnTo
	}
	var auditTenant *uuid.UUID
	if ml.TenantID.Valid {
		t := uuid.UUID(ml.TenantID.Bytes)
		auditTenant = &t
	} else if account.TenantID.Valid {
		auditTenant = &res.TenantID
	}
	target := account.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     auditTenant,
		ActorUserID:  &target,
		ActorType:    "system",
		Action:       "auth.magic_link_consumed",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           ac.IP,
		UserAgent:    ac.UserAgent,
		RequestID:    ac.RequestID,
		Metadata:     map[string]any{"app": ml.App},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}
