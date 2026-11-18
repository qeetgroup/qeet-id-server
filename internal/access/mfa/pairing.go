package mfa

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A phone is linked to an account with a pairing code: the signed-in person
// asks for one, the console shows it, and the mobile app exchanges it once for
// its device credential, so no access token is ever copied.
const (
	pushPairingTTL      = 5 * time.Minute // how long a code can link a phone
	pushPairingsPerHour = 10              // codes one person may ask for per hour
	pairingCodeLength   = 10              // 5 bits per character: 50 bits against a throttled claim route
)

// pairingAlphabet is Crockford's base32: no I, L, O or U, so a code read
// off a screen and typed cannot be mistaken.
const pairingAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// PushPairing is a pairing code as its owner sees it. Status is pending (it
// can still link a phone), linked (it did; DeviceID names the phone) or
// expired (it timed out, was replaced by a newer code, or was withdrawn).
type PushPairing struct {
	ID        uuid.UUID  `json:"id"`
	Status    string     `json:"status"`
	ExpiresAt time.Time  `json:"expires_at"`
	DeviceID  *uuid.UUID `json:"device_id,omitempty"`
}

// newPairingCode returns a fresh code, grouped for reading ("ABCDE-FGHJK").
func newPairingCode() (string, error) {
	b := make([]byte, pairingCodeLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, pairingCodeLength+1)
	for i, c := range b {
		if i == pairingCodeLength/2 {
			out = append(out, '-')
		}
		out = append(out, pairingAlphabet[c&31]) // 256 is a multiple of 32: unbiased
	}
	return string(out), nil
}

// normalizePairingCode reads a code as typed or scanned: case, spaces and
// hyphens do not matter, and O, I and L read as 0, 1 and 1. "" when it cannot
// be a code.
func normalizePairingCode(raw string) string {
	var out strings.Builder
	for _, r := range strings.ToUpper(raw) {
		switch r {
		case ' ', '-':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(pairingAlphabet, r) {
			return ""
		}
		out.WriteRune(r)
	}
	if out.Len() != pairingCodeLength {
		return ""
	}
	return out.String()
}

// CreatePushPairing issues a single-use code that can link a phone to userID's
// account for pushPairingTTL, ending their earlier unused codes, recorded in
// by's organization as userID's from by's request. The code is returned only
// here. Past pushPairingsPerHour it fails with retry_after.
func (s *Service) CreatePushPairing(ctx context.Context, userID uuid.UUID, by Caller) (PushPairing, string, error) {
	code, err := newPairingCode()
	if err != nil {
		return PushPairing{}, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushPairing{}, "", err
	}
	defer tx.Rollback(ctx)
	// One request at a time per person, so two cannot both pass the limit.
	// Raw SQL: pg_advisory_xact_lock returns void, which sqlc cannot model.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mfa_push_pairing:' || $1::text, 0))`, userID); err != nil {
		return PushPairing{}, "", err
	}
	q := s.q.WithTx(tx)
	recent, err := q.RecentPushPairings(ctx, userID)
	if err != nil {
		return PushPairing{}, "", err
	}
	if recent.Issued >= pushPairingsPerHour {
		wait := time.Until(recent.Oldest.Add(time.Hour))
		return PushPairing{}, "", errs.ErrTooManyRequests.WithMetadata(map[string]any{
			"retry_after": max(1, int(wait.Round(time.Second).Seconds()))})
	}
	if err := q.ExpireLivePushPairings(ctx, userID); err != nil {
		return PushPairing{}, "", err
	}
	row, err := q.InsertPushPairing(ctx, dbgen.InsertPushPairingParams{
		UserID: userID, OrganizationID: by.OrganizationID, CodeHash: secretHash(normalizePairingCode(code)),
		TtlSeconds: pushPairingTTL.Seconds(),
	})
	if err != nil {
		return PushPairing{}, "", err
	}
	p := PushPairing{ID: row.ID, Status: "pending", ExpiresAt: row.ExpiresAt}
	if err := audit.Record(ctx, tx, as(by.Actor, "user", userID).EventIn(by.OrganizationID, "mfa.push_pairing_created", "push_pairing", p.ID,
		map[string]any{"expires_at": p.ExpiresAt})); err != nil {
		return PushPairing{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return PushPairing{}, "", err
	}
	return p, code, nil
}

// GetPushPairing returns one of userID's pairing codes; not found when it is
// someone else's.
func (s *Service) GetPushPairing(ctx context.Context, userID, id uuid.UUID) (PushPairing, error) {
	row, err := s.q.GetPushPairing(ctx, dbgen.GetPushPairingParams{ID: id, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return PushPairing{}, errs.ErrNotFound
	}
	if err != nil {
		return PushPairing{}, err
	}
	p := PushPairing{ID: id, ExpiresAt: row.ExpiresAt, DeviceID: row.DeviceID}
	switch {
	case row.UsedAt != nil:
		p.Status = "linked"
	case !time.Now().Before(p.ExpiresAt):
		p.Status = "expired"
	default:
		p.Status = "pending"
	}
	return p, nil
}

// WithdrawPushPairing stops one of userID's unused pairing codes working, as
// when the screen showing it is closed. A code that already linked a phone is
// left as it is (remove the phone instead); not found when it is someone
// else's.
func (s *Service) WithdrawPushPairing(ctx context.Context, userID, id uuid.UUID) error {
	found, err := s.q.WithdrawPushPairing(ctx, dbgen.WithdrawPushPairingParams{ID: id, UserID: userID})
	if err != nil {
		return err
	}
	if !found {
		return errs.ErrNotFound
	}
	return nil
}

// PushPairingClaim is what a phone gets for a pairing code: whose account it
// is now linked to, the device record and its device credential (shown only
// now).
type PushPairingClaim struct {
	UserID      uuid.UUID           `json:"user_id"`
	Device      PushDevice          `json:"device"`
	DeviceToken string              `json:"device_token"`
	Account     *PushPairingAccount `json:"account,omitempty"`
}

// PushPairingAccount names the account the phone now approves sign-ins for, so the app can
// show it. Only the holder of the one-time pairing code, which the signed-in person asked for,
// receives it.
type PushPairingAccount struct {
	Email string `json:"email"`
}

// ClaimPushPairing links the phone presenting code to the account that asked for it, as
// RegisterPushDevice does, and uses the code up. A wrong, used or expired code, or one for an inactive
// account, gets the same ErrMFAPairingCodeInvalid. Audited as mfa.push_device_linked, the phone the
// actor, from the request from.
func (s *Service) ClaimPushPairing(ctx context.Context, code, name, pushToken, platform string, from audit.Actor) (PushPairingClaim, error) {
	normalized := normalizePairingCode(code)
	if normalized == "" {
		return PushPairingClaim{}, ErrPairingCodeInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushPairingClaim{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	pairing, err := q.ClaimablePushPairing(ctx, secretHash(normalized))
	if errors.Is(err, pgx.ErrNoRows) {
		return PushPairingClaim{}, ErrPairingCodeInvalid
	}
	if err != nil {
		return PushPairingClaim{}, err
	}
	device, token, err := s.registerPushDeviceTx(ctx, tx, pairing.UserID, name, pushToken, platform)
	if err != nil {
		return PushPairingClaim{}, err
	}
	if err := q.UsePushPairing(ctx, dbgen.UsePushPairingParams{ID: pairing.ID, DeviceID: &device.ID}); err != nil {
		return PushPairingClaim{}, err
	}
	if err := audit.Record(ctx, tx, as(from, "device", pairing.UserID).EventIn(pairing.OrganizationID, "mfa.push_device_linked",
		"push_device", device.ID, map[string]any{"pairing_id": pairing.ID, "platform": device.Platform})); err != nil {
		return PushPairingClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PushPairingClaim{}, err
	}
	return PushPairingClaim{UserID: pairing.UserID, Device: device, DeviceToken: token, Account: &PushPairingAccount{Email: pairing.Email}}, nil
}

// PurgeExpiredPushPairings deletes pairing codes that expired longer ago than
// retention, used or not, and returns how many. Run on a schedule.
func PurgeExpiredPushPairings(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	q, cutoff := dbgen.New(pool), time.Now().UTC().Add(-retention)
	return postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.PurgeExpiredPushPairings(ctx, dbgen.PurgeExpiredPushPairingsParams{Cutoff: cutoff, MaxRows: limit})
	})
}

// --- HTTP: the signed-in person (authenticated) ---

// createPushPairing → POST /v1/mfa/push/pairing.
func (h *Handler) createPushPairing(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	pairing, code, err := h.Service.CreatePushPairing(r.Context(), *p.UserID, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": pairing.ID, "code": code, "status": pairing.Status, "expires_at": pairing.ExpiresAt,
	})
}

// pairingInScope reads the {id} of one of the caller's own pairing codes.
func pairingInScope(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return uuid.Nil, uuid.Nil, false
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	return *p.UserID, id, true
}

// getPushPairing → GET /v1/mfa/push/pairing/{id}: whether the code has
// linked a phone yet, for the screen showing it.
func (h *Handler) getPushPairing(w http.ResponseWriter, r *http.Request) {
	userID, id, ok := pairingInScope(w, r)
	if !ok {
		return
	}
	pairing, err := h.Service.GetPushPairing(r.Context(), userID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pairing)
}

// withdrawPushPairing → DELETE /v1/mfa/push/pairing/{id}.
func (h *Handler) withdrawPushPairing(w http.ResponseWriter, r *http.Request) {
	userID, id, ok := pairingInScope(w, r)
	if !ok {
		return
	}
	if err := h.Service.WithdrawPushPairing(r.Context(), userID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- HTTP: the phone (public) ---

type claimPushPairingInput struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	PushToken string `json:"push_token"`
	Platform  string `json:"platform"`
}

// claimPushPairing → POST /v1/mfa/push/pairing/claim: the mobile app, holding
// no session, links the phone it runs on with a pairing code.
func (h *Handler) claimPushPairing(w http.ResponseWriter, r *http.Request) {
	var in claimPushPairingInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Code == "" || in.PushToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("code and push_token required"))
		return
	}
	if in.Platform != "ios" && in.Platform != "android" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("platform must be ios or android"))
		return
	}
	claim, err := h.Service.ClaimPushPairing(r.Context(), in.Code, in.Name, in.PushToken, in.Platform, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellPhoneLinked(r.Context(), claim.UserID)
	httpx.WriteJSON(w, http.StatusCreated, claim)
}
