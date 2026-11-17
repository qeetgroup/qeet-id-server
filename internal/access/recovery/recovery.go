// Package recovery handles forgot-password and magic-link sign-in. Each emails
// a single-use link whose token is stored only as a hash; following it resets
// the password or starts a sign-in.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/access/accountnotice"
	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// AuditCtx is the client context of a recovery request, for its audit rows.
// These flows have no signed-in principal.
type AuditCtx struct {
	IP        string
	UserAgent string
	RequestID string
}

// Service runs password resets and magic links. Email links go to baseAppURL
// (the console), or to loginBaseURL for a request made from hosted login.
// Until SetPasswordRules is called resets are refused rather than set an
// unchecked password; the other Set* dependencies are optional.
type Service struct {
	pool            *pgxpool.Pool
	q               *dbgen.Queries
	sender          notifier.Sender
	ttl             time.Duration
	baseAppURL      string
	loginBaseURL    string
	rules           PasswordRules
	magicLinks      MagicLinkPolicy
	capture         auth.DomainCapture
	magicPerAddress Limiter
	magicPerCaller  Limiter
	resetPerAddress Limiter
	signals         *sessionsignal.Signaller
	requestRecords  Limiter
	// deliveries tracks the work requests leave running; see afterAnswer.
	deliveries sync.WaitGroup
}

// PasswordRules checks a new password against the rules of the account's
// organization (uuid.Nil: the platform baseline), the offline strength check
// and, when enabled, the breach check. Satisfied by *authpolicy.Service.
type PasswordRules interface {
	ValidateForOrganization(ctx context.Context, organizationID uuid.UUID, email, pw string) error
}

// MagicLinkPolicy is the slice of the authentication policy that decides
// whether an organization allows magic-link sign-in and how long its links
// live. Satisfied by *authpolicy.Service.
type MagicLinkPolicy interface {
	MagicLinkPolicy(ctx context.Context, organizationID uuid.UUID) (enabled bool, ttl time.Duration, err error)
}

// SetDomainCapture sets the check that refuses resets and magic links to an
// address whose organization requires single sign-on (nil: none is refused).
func (s *Service) SetDomainCapture(c auth.DomainCapture) { s.capture = c }

// refuseCaptured returns errs.ErrAuthSSORequired when email's domain is
// captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	if s.capture == nil {
		return nil
	}
	return s.capture.RefuseCaptured(ctx, email)
}

// SetSessionSignals sets how ended sessions are announced.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// SetMagicLinkPolicy sets the policy that decides whether an organization
// allows magic links and how long they live.
func (s *Service) SetMagicLinkPolicy(p MagicLinkPolicy) { s.magicLinks = p }

// magicLinkTTL is how long a magic link for organizationID lives, or
// ErrAuthMethodDisabled when the organization has switched magic links off
// (uuid.Nil: no organization, the platform default).
func (s *Service) magicLinkTTL(ctx context.Context, organizationID uuid.UUID) (time.Duration, error) {
	// No organization, no organization policy: the platform allows magic
	// links, with the default lifetime.
	if s.magicLinks == nil || organizationID == uuid.Nil {
		return s.ttl, nil
	}
	enabled, ttl, err := s.magicLinks.MagicLinkPolicy(ctx, organizationID)
	if err != nil {
		return 0, err
	}
	if !enabled {
		return 0, errs.ErrAuthMethodDisabled
	}
	if ttl <= 0 {
		return s.ttl, nil
	}
	return ttl, nil
}

// NewService returns the password reset and magic link service.
func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL string) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl, baseAppURL: baseAppURL,
		// Ten records per account, then one a minute.
		requestRecords: ratelimit.New(1.0/60, 10)}
}

// SetPasswordRules sets the password check run on reset.
func (s *Service) SetPasswordRules(r PasswordRules) { s.rules = r }

// SetHostedLogin sets the hosted login origin, so a reset requested there links
// back to its own reset page.
func (s *Service) SetHostedLogin(loginBaseURL string) { s.loginBaseURL = loginBaseURL }

// AppHostedLogin marks a reset requested from the hosted login (ResetOrigin.App).
const AppHostedLogin = "hosted_login"

// ResetOrigin says where a password reset was requested from, which decides
// where its emailed link lands.
type ResetOrigin struct {
	App      string   // AppHostedLogin for hosted login; anything else means the console
	ReturnTo string   // hosted login only: where to continue, already validated by the caller
	Audit    AuditCtx // the request, for its audit record
}

// resetLink builds the emailed reset link: hosted login's own reset page for a
// reset requested there, the console's reset screen otherwise. The token goes
// last, after any return_to.
func (s *Service) resetLink(raw string, from ResetOrigin) string {
	if from.App == AppHostedLogin && s.loginBaseURL != "" {
		q := url.Values{}
		if from.ReturnTo != "" {
			q.Set("return_to", from.ReturnTo)
		}
		prefix := ""
		if len(q) > 0 {
			prefix = q.Encode() + "&"
		}
		return fmt.Sprintf("%s/reset-password?%stoken=%s", s.loginBaseURL, prefix, url.QueryEscape(raw))
	}
	return fmt.Sprintf("%s/forgot-password?token=%s", s.baseAppURL, raw)
}

// SetResetLimit bounds password-reset requests per address (nil: unbounded).
func (s *Service) SetResetLimit(perAddress Limiter) { s.resetPerAddress = perAddress }

// StartPasswordReset emails a reset link to the account with this email, if
// any (email is globally unique), landing back on the application from names
// (see resetLink). It answers alike either way, storing and sending the link
// after it returns (see afterAnswer), and returns the raw token for dev-mode
// handlers, empty when no account matched. The link goes to the address as
// stored, and ends the account's earlier ones. Past the per-address bound it
// returns ErrTooManyRequests, whether or not an account matched; an address
// whose organization requires single sign-on is then refused before any
// account is looked up.
func (s *Service) StartPasswordReset(ctx context.Context, email string, from ResetOrigin) (string, error) {
	if s.resetPerAddress != nil {
		if ok, _ := s.resetPerAddress.Take(ctx, "password-reset:address:"+strings.ToLower(strings.TrimSpace(email))); !ok {
			return "", errs.ErrTooManyRequests
		}
	}
	if err := s.refuseCaptured(ctx, email); err != nil {
		return "", err
	}
	var userID uuid.UUID
	var organizationID *uuid.UUID
	var stored string
	err := s.pool.QueryRow(ctx,
		`SELECT id, organization_id, email FROM account.users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`, email,
	).Scan(&userID, &organizationID, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	resetURL := s.resetLink(raw, from)
	s.afterAnswer(ctx, "send a password reset link", func(ctx context.Context) error {
		if err := s.q.ExpirePasswordResets(ctx, userID); err != nil {
			return err
		}
		if err := s.q.InsertPasswordReset(ctx, dbgen.InsertPasswordResetParams{
			UserID:    userID,
			TokenHash: hash,
			ExpiresAt: time.Now().UTC().Add(s.ttl),
		}); err != nil {
			return err
		}
		if err := s.sender.Send(ctx, notifier.Message{
			Channel: "email",
			To:      stored,
			Subject: "Reset your password",
			Body:    fmt.Sprintf("Reset your Qeet ID password: %s", resetURL),
			HTML: emailtmpl.Action(
				"Reset your password",
				"We received a request to reset the password for your Qeet ID account. Click the button below to choose a new one.",
				"Reset password", resetURL,
				"If you didn't request a password reset, you can safely ignore this email — your password won't change.",
			),
		}); err != nil {
			return err
		}
		var orgs []uuid.UUID
		if organizationID != nil {
			orgs = []uuid.UUID{*organizationID}
		}
		s.recordRequest(ctx, "auth.password_reset_requested", userID, orgs, from.Audit, map[string]any{"app": from.App})
		return nil
	})
	return raw, nil
}

// deliveryTimeout bounds what a recovery request leaves running once answered.
const deliveryTimeout = 30 * time.Second

// afterAnswer runs work, such as storing and emailing a link, without the
// request waiting for it, so neither its duration nor its failure shows in an
// answer that must be the same for an address with no account. A failure is
// logged.
func (s *Service) afterAnswer(ctx context.Context, what string, work func(ctx context.Context) error) {
	ctx = context.WithoutCancel(ctx)
	s.deliveries.Add(1)
	go func() {
		defer s.deliveries.Done()
		ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
		defer cancel()
		if err := work(ctx); err != nil {
			slog.Warn("recovery: "+what, "err", err)
		}
	}()
}

// Wait blocks until the work answered requests left running is done, so a
// shutdown doesn't drop a link a request already said was sent.
func (s *Service) Wait() { s.deliveries.Wait() }

// unrecordedRequests counts recovery requests left out of the audit trail by
// recordRequest's bound.
var unrecordedRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "recovery_requests_unrecorded_total",
	Help: "Password-reset and magic-link requests not written to the audit trail because the bound per account was reached, by action.",
}, []string{"action"})

func init() {
	// Publish every series at zero so an alert can rate() it from the start.
	for _, action := range []string{"auth.password_reset_requested", "auth.magic_link_requested"} {
		unrecordedRequests.WithLabelValues(action)
	}
}

// recordRequest records a recovery request in the audit trail of each of orgs
// (none: no organization's), naming the account as the subject, not the actor,
// since whoever asked may not own it. It is bounded per account and best
// effort: a record that can't be written is logged.
func (s *Service) recordRequest(ctx context.Context, action string, userID uuid.UUID, orgs []uuid.UUID, ac AuditCtx, meta map[string]any) {
	if s.requestRecords != nil {
		if ok, _ := s.requestRecords.Take(ctx, action+":"+userID.String()); !ok {
			unrecordedRequests.WithLabelValues(action).Inc()
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	err := func() error {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		subject := userID
		for _, org := range auditOrgs(orgs) {
			if err := audit.Record(ctx, tx, audit.Event{
				OrganizationID: org, ActorType: "anonymous", Action: action, ResourceType: "user", ResourceID: &subject,
				IP: ac.IP, UserAgent: ac.UserAgent, RequestID: ac.RequestID, Metadata: meta,
			}); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}()
	if err != nil {
		slog.Warn("recovery: record a request", "action", action, "err", err)
	}
}

// proveAddress marks userID's address verified inside tx after a link sent to
// it was used (proof names which). The first proof also removes every
// credential set up before it, keeping the password only if keepPassword, and
// records both in org's trail. proved reports whether this was the first proof.
func proveAddress(ctx context.Context, tx pgx.Tx, userID uuid.UUID, org *uuid.UUID, proof string, keepPassword bool, ac AuditCtx) (proved bool, err error) {
	email, err := dbgen.New(tx).VerifyEmailByLink(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	removed, err := auth.ForgetCredentials(ctx, tx, userID, keepPassword)
	if err != nil {
		return false, err
	}
	subject := userID
	for _, e := range []struct {
		action string
		meta   map[string]any
	}{
		{"email.verified", map[string]any{"email": email, "proof": proof}},
		{"auth.credentials_removed", map[string]any{"proof": proof, "removed": removed}},
	} {
		if err := audit.Record(ctx, tx, audit.Event{
			OrganizationID: org, ActorUserID: &subject, ActorType: "user", Action: e.action, ResourceType: "user",
			ResourceID: &subject, IP: ac.IP, UserAgent: ac.UserAgent, RequestID: ac.RequestID, Metadata: e.meta,
		}); err != nil {
			return false, err
		}
	}
	return true, nil
}

// auditOrgs is each distinct organization in orgs, as an audit row names it, or
// one nil (no organization's trail) when there are none.
func auditOrgs(orgs []uuid.UUID) []*uuid.UUID {
	var out []*uuid.UUID
	for i, org := range orgs {
		if org != uuid.Nil && !slices.Contains(orgs[:i], org) {
			out = append(out, &orgs[i])
		}
	}
	if len(out) == 0 {
		return []*uuid.UUID{nil}
	}
	return out
}

// ConfirmPasswordReset sets a new password with a reset link, checked against
// the rules of the account's organization once the link is known to be good. A
// refused password, or an address that must now sign in with single sign-on,
// leaves the credential and link untouched. On success the address counts as
// verified and every sign-in ends (see auth.EndSignIns).
func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string, ac AuditCtx) error {
	if s.rules == nil {
		return errs.ErrNotImplemented
	}
	hash := codes.Hash(rawToken)
	// The password is checked before the transaction, as the check reads the
	// organization's rules and may call the breach service; the link is
	// checked again under lock inside it.
	row, err := resetLink(ctx, s.q, hash)
	if err != nil {
		return err
	}
	account, err := s.q.GetResetAccount(ctx, row.UserID)
	if err != nil {
		return err
	}
	if err := s.refuseCaptured(ctx, account.Email); err != nil {
		return err
	}
	var organizationID uuid.UUID // uuid.Nil: the account belongs to no organization
	var orgOf *uuid.UUID         // the trail the reset is recorded in
	if account.OrganizationID.Valid {
		organizationID = account.OrganizationID.Bytes
		orgOf = &organizationID
	}
	if err := s.rules.ValidateForOrganization(ctx, organizationID, account.Email, newPassword); err != nil {
		return err
	}
	pwHash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	qtx := s.q.WithTx(tx)
	if row, err = resetLink(ctx, qtx, hash); err != nil {
		return err
	}
	if err := qtx.UpsertPasswordCredential(ctx, dbgen.UpsertPasswordCredentialParams{
		UserID:       row.UserID,
		PasswordHash: pwHash,
	}); err != nil {
		return err
	}
	if err := qtx.MarkPasswordResetUsed(ctx, row.ID); err != nil {
		return err
	}
	// The link reached the address and nobody else: it proves the address,
	// so an account registered with it unproved becomes the owner's here —
	// everything set up before but the new password goes, and every session
	// it had ends below.
	if _, err := proveAddress(ctx, tx, row.UserID, orgOf, "password_reset", true, ac); err != nil {
		return err
	}
	// End every sign-in the old password could have opened, and announce the
	// ended sessions: sessions, hosted sessions, remembered devices,
	// application grants and pending authorisations.
	ended, err := auth.EndSignIns(ctx, tx, s.signals, row.UserID, sessionsignal.ReasonPasswordReset)
	if err != nil {
		return err
	}
	userID := row.UserID
	target := userID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: orgOf,
		ActorUserID:    &target,
		ActorType:      "system",
		Action:         "auth.password_reset_confirmed",
		ResourceType:   "user",
		ResourceID:     &target,
		IP:             ac.IP,
		UserAgent:      ac.UserAgent,
		RequestID:      ac.RequestID,
		Metadata: map[string]any{
			"sessions_revoked": true, "revoked_sessions": ended.Sessions, "revoked_login_sessions": ended.LoginSessions,
			"revoked_app_grants": ended.AppGrants, "revoked_trusted_devices": ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	accountnotice.Tell(ctx, s.pool, s.sender, userID, "Your password was reset",
		"The password for your Qeet ID account was reset with a link sent to this address, and you were signed out everywhere.")
	return nil
}

// resetLink reads the reset link hash names through q, refusing one that is
// unknown, used or expired.
func resetLink(ctx context.Context, q *dbgen.Queries, hash string) (dbgen.GetPasswordResetByTokenRow, error) {
	row, err := q.GetPasswordResetByToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errs.ErrResetLinkInvalid
	}
	if err != nil {
		return row, err
	}
	if row.UsedAt.Valid {
		return row, errs.ErrRecoveryLinkUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return row, errs.ErrRecoveryLinkExpired
	}
	return row, nil
}
