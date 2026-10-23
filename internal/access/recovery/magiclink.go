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
	Email     string    // the address to send the link to
	TenantID  uuid.UUID // organisation whose sign-in page asked; uuid.Nil for the console
	App       string    // MagicLinkHostedLogin, or anything else for the console
	ReturnTo  string    // hosted login only: where the journey continues, checked by the caller
	Caller    string    // requester's IP, for the per-caller bound
	UserAgent string    // requester's User-Agent, for the audit record
}

// Limiter bounds how often something may happen per key. Satisfied by
// *ratelimit.Limiter.
type Limiter interface {
	Take(ctx context.Context, key string) (bool, int)
}

// SetMagicLinkLimits bounds magic-link requests per address and per caller
// (nil: unbounded).
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

// RequestMagicLink emails a sign-in link to the account holding req.Email, if
// any, storing and sending it after it returns (see afterAnswer), so it answers
// alike either way. It returns ErrTooManyRequests past the bounds, and
// ErrAuthMethodDisabled when the asking organisation has magic links off.
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
	s.afterAnswer(ctx, "send a magic link", func(ctx context.Context) error {
		return s.sendMagicLink(ctx, req, account, ttl)
	})
	return nil
}

// sendMagicLink stores and emails a link for account, requested by req; ttl
// is the asking organisation's link lifetime (zero for a console request,
// which the account's own organisation decides).
func (s *Service) sendMagicLink(ctx context.Context, req MagicLinkRequest, account dbgen.GetMagicLinkAccountRow, ttl time.Duration) error {
	if req.TenantID == uuid.Nil {
		// From the console: the account's own organisation decides.
		var err error
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

// MagicLinkResult is what consuming a magic link signs in.
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
	hash := codes.Hash(rawToken)
	ml, account, err := magicLink(ctx, s.q, hash, app)
	if err != nil {
		return nil, err
	}
	// A link issued before its organisation switched magic links off stops
	// working too; it stays unused. A console link answers to the account's
	// own organisation. The policy is read before the transaction, and the
	// link checked again under lock inside it.
	policyTenant := uuid.UUID(ml.TenantID.Bytes)
	if !ml.TenantID.Valid {
		policyTenant = uuid.UUID(account.TenantID.Bytes)
	}
	if _, err := s.magicLinkTTL(ctx, policyTenant); err != nil {
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

// magicLink reads, through q, the link for app that hash names and the
// account it signs in to, refusing a link that is unknown, used or expired.
func magicLink(ctx context.Context, q *dbgen.Queries, hash, app string) (dbgen.GetMagicLinkByTokenRow, dbgen.GetMagicLinkAccountRow, error) {
	var account dbgen.GetMagicLinkAccountRow
	ml, err := q.GetMagicLinkByToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && ml.App != app) {
		return ml, account, errs.ErrMagicLinkInvalid
	}
	if err != nil {
		return ml, account, err
	}
	if ml.UsedAt.Valid {
		return ml, account, errs.ErrRecoveryLinkUsed
	}
	if time.Now().After(ml.ExpiresAt) {
		return ml, account, errs.ErrRecoveryLinkExpired
	}
	account, err = q.GetMagicLinkAccount(ctx, ml.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return ml, account, errs.ErrMagicLinkInvalid
	}
	return ml, account, err
}
