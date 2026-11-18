// Package mfa implements second factors: authenticator apps (TOTP) with
// hashed recovery codes, email and SMS codes, push approval on a linked phone
// and passkeys, plus session step-up. Each change commits in one transaction
// with its audit row.
package mfa

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/accountnotice"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service manages a user's second factors and session step-ups.
type Service struct {
	pool        *pgxpool.Pool             // database pool
	q           *dbgen.Queries            // generated queries
	issuer      string                    // issuer name shown in the authenticator app
	sender      notifier.Sender           // delivers email and SMS codes
	apns        *apnsClient               // Apple Push Notification service for the iOS app (EnableAPNs; nil = off)
	fcm         *fcmClient                // Firebase Cloud Messaging for the Android app (EnableFCM; nil = off)
	box         *envelope.Cipher          // encrypts TOTP secrets and push tokens (SetCipher)
	webauthn    WebAuthnVerifier          // passkeys as a sign-in second factor (nil = not offered)
	plan        entitlements.PlanGate     // gates SMS codes by plan (nil = no gate)
	deliverable func(channel string) bool // whether a channel can deliver (nil = assume it can)
}

// tellAccountChange emails userID that how they sign in changed, after the
// change has committed (accountnotice.Tell).
func (s *Service) tellAccountChange(ctx context.Context, userID uuid.UUID, subject, intro string) {
	accountnotice.Tell(ctx, s.pool, s.sender, userID, subject, intro)
}

// tellPhoneLinked emails userID that a phone can now approve their sign-ins.
func (s *Service) tellPhoneLinked(ctx context.Context, userID uuid.UUID) {
	s.tellAccountChange(ctx, userID, "A phone was linked to approve your sign-ins",
		"A phone was linked to your Qeet ID account and can now approve your sign-ins.")
}

// tellPhoneUnlinked emails userID that a phone no longer approves their
// sign-ins.
func (s *Service) tellPhoneUnlinked(ctx context.Context, userID uuid.UUID) {
	s.tellAccountChange(ctx, userID, "A phone was unlinked from your account",
		"A phone that approved your sign-ins was unlinked from your Qeet ID account.")
}

// NewService returns the second-factor service.
func NewService(pool *pgxpool.Pool, issuer string, sender notifier.Sender) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, sender: sender}
}

// SetCipher sets the cipher that encrypts second-factor secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetPlan wires the plan gate for SMS codes, a paid feature (it also costs per
// message): every SMS code, at setup, step-up and sign-in, is refused unless
// the organization's plan includes sms_mfa, and refused outright with no
// organization.
func (s *Service) SetPlan(p entitlements.PlanGate) { s.plan = p }

// SetDeliveryCheck wires the check that a channel can deliver a code
// (notifier.Router.Configured). A code for a channel that cannot is refused
// with ErrMFADeliveryUnavailable before anything is stored.
func (s *Service) SetDeliveryCheck(deliverable func(channel string) bool) {
	s.deliverable = deliverable
}

// Caller is who changes or proves a person's own second factors: their
// request's audit actor, the organization the change is recorded in (nil:
// none) and the session a proved factor steps up (nil: none).
type Caller struct {
	audit.Actor
	OrganizationID *uuid.UUID
	SessionID      *uuid.UUID
}

// CallerOf is r's signed-in caller.
func CallerOf(r *http.Request) Caller {
	c := Caller{Actor: audit.ActorOf(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		c.OrganizationID, c.SessionID = p.OrganizationID, p.SessionID
	}
	return c
}

// event is the audit event of action on userID's account by c.
func (c Caller) event(action string, userID uuid.UUID, metadata map[string]any) audit.Event {
	return c.EventIn(c.OrganizationID, action, "user", userID, metadata)
}

// as is from's provenance (client address, user agent, request ID) recorded
// as actorType acting as userID.
func as(from audit.Actor, actorType string, userID uuid.UUID) audit.Actor {
	from.Type, from.UserID = actorType, &userID
	return from
}

// inTx runs fn in a transaction, committed when fn succeeds.
func (s *Service) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}
