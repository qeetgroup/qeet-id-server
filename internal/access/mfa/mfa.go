// Package mfa implements second factors: authenticator apps (TOTP) with
// hashed recovery codes, email and SMS codes, push approval on a linked phone
// and passkeys, plus session step-up. Mutating methods take a pgx.Tx so the
// caller commits the change and its audit row together.
package mfa

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service manages a user's second factors and session step-ups.
type Service struct {
	pool            *pgxpool.Pool             // database pool
	q               *dbgen.Queries            // generated queries
	issuer          string                    // issuer name shown in the authenticator app
	sender          notifier.Sender           // delivers email and SMS codes
	pushURL         string                    // Expo push API endpoint ("" = push delivery off)
	pushAccessToken string                    // sent to the push service when set (SetExpoAccessToken)
	box             *envelope.Cipher          // encrypts TOTP secrets and push tokens (SetCipher)
	webauthn        WebAuthnVerifier          // passkeys as a sign-in second factor (nil = not offered)
	plan            PlanGate                  // gates SMS codes by plan (nil = no gate)
	deliverable     func(channel string) bool // whether a channel can deliver (nil = assume it can)
}

// NewService returns the second-factor service.
func NewService(pool *pgxpool.Pool, issuer string, sender notifier.Sender, pushURL string) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, sender: sender, pushURL: pushURL}
}

// SetCipher sets the cipher that encrypts second-factor secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetPlan wires the plan gate for SMS codes, a paid feature (it also costs per
// message): every SMS code, at setup, step-up and sign-in, is refused unless
// the organisation's plan includes sms_mfa, and refused outright with no
// organisation.
func (s *Service) SetPlan(p PlanGate) { s.plan = p }

// SetDeliveryCheck wires the check that a channel can deliver a code
// (notifier.Router.Configured). A code for a channel that cannot is refused
// with ErrMFADeliveryUnavailable before anything is stored.
func (s *Service) SetDeliveryCheck(deliverable func(channel string) bool) {
	s.deliverable = deliverable
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an MFA mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// Email / SMS OTP factors

// Step-up MFA. A step-up records that one session met a second factor
// recently, so a factor proved in one browser never unlocks another. Each
// organisation sets how long it lasts (step_up_window, default 5 minutes) and
// which factor types count (step_up_methods, default any).

// --- OTP factor handlers ---

// --- WebAuthn second-factor handlers ---

// --- Step-up status ---
