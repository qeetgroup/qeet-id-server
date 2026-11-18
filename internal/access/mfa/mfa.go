// Package mfa implements second factors: authenticator apps (TOTP) with
// hashed recovery codes, email and SMS codes, push approval on a linked phone
// and passkeys, plus session step-up. Each change commits in one transaction
// with its audit row.
package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/accountnotice"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
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
	apns        *apnsClient               // Apple Push Notification service for the iOS app (nil = not configured)
	fcm         *fcmClient                // Firebase Cloud Messaging for the Android app (nil = not configured)
	box         *envelope.Cipher          // encrypts TOTP secrets and push tokens
	webauthn    WebAuthnVerifier          // passkeys as a sign-in second factor
	plan        entitlements.PlanGate     // gates SMS codes by plan
	deliverable func(channel string) bool // whether a channel can deliver a code
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

// Deps are what the second-factor service is built from. Every field is
// required except APNs and FCM, the phone platforms a deployment pushes to.
type Deps struct {
	Issuer string           // the issuer name shown in the authenticator app
	Sender notifier.Sender  // delivers email and SMS codes
	Cipher *envelope.Cipher // encrypts TOTP secrets and push tokens at rest
	// Plan gates SMS codes, a paid feature that also costs per message: every
	// SMS code, at setup, step-up and sign-in, is refused unless the
	// organization's plan includes sms_mfa, and refused with no organization.
	Plan entitlements.PlanGate
	// Deliverable says whether a channel can deliver a code
	// (notifier.Router.Configured); a code it can't is refused with
	// ErrDeliveryUnavailable before anything is stored.
	Deliverable func(channel string) bool
	WebAuthn    WebAuthnVerifier // passkeys as a sign-in second factor
	APNs        *APNsConfig      // push to the iOS app (nil: none)
	FCM         *FCMConfig       // push to the Android app (nil: none)
}

// NewService returns the second-factor service built from d. It fails on a
// missing dependency, or a push setting that can't work, so a misconfigured
// server stops at start-up rather than at the first sign-in.
func NewService(pool *pgxpool.Pool, d Deps) (*Service, error) {
	switch {
	case d.Sender == nil:
		return nil, errors.New("mfa: the second-factor service needs a sender")
	case d.Cipher == nil:
		return nil, errors.New("mfa: the second-factor service needs a cipher")
	case d.Plan == nil:
		return nil, errors.New("mfa: the second-factor service needs a plan gate")
	case d.Deliverable == nil:
		return nil, errors.New("mfa: the second-factor service needs a delivery check")
	case d.WebAuthn == nil:
		return nil, errors.New("mfa: the second-factor service needs a passkey verifier")
	}
	s := &Service{pool: pool, q: dbgen.New(pool), issuer: d.Issuer, sender: d.Sender, box: d.Cipher,
		plan: d.Plan, deliverable: d.Deliverable, webauthn: d.WebAuthn}
	if d.APNs != nil {
		if err := s.enableAPNs(*d.APNs); err != nil {
			return nil, fmt.Errorf("mfa: push to the iOS app: %w", err)
		}
	}
	if d.FCM != nil {
		if err := s.enableFCM(*d.FCM); err != nil {
			return nil, fmt.Errorf("mfa: push to the Android app: %w", err)
		}
	}
	return s, nil
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
