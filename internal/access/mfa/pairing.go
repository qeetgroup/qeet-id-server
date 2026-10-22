package mfa

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
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
// account for pushPairingTTL, ending their earlier unused codes. The code is
// returned only here. Past pushPairingsPerHour it fails with retry_after.
func (s *Service) CreatePushPairing(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, ip, ua string) (PushPairing, string, error) {
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mfa_push_pairing:' || $1::text, 0))`, userID); err != nil {
		return PushPairing{}, "", err
	}
	var issued int
	var oldest *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT count(*), min(created_at) FROM auth.mfa_push_pairings
		WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'
	`, userID).Scan(&issued, &oldest); err != nil {
		return PushPairing{}, "", err
	}
	if issued >= pushPairingsPerHour {
		wait := time.Hour
		if oldest != nil {
			wait = time.Until(oldest.Add(time.Hour))
		}
		return PushPairing{}, "", errs.ErrTooManyRequests.WithMetadata(map[string]any{
			"retry_after": max(1, int(wait.Round(time.Second).Seconds()))})
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_push_pairings SET expires_at = NOW()
		WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`, userID); err != nil {
		return PushPairing{}, "", err
	}
	p := PushPairing{Status: "pending"}
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.mfa_push_pairings (user_id, tenant_id, code_hash, expires_at)
		VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))
		RETURNING id, expires_at
	`, userID, tenantID, secretHash(normalizePairingCode(code)), pushPairingTTL.Seconds()).Scan(&p.ID, &p.ExpiresAt); err != nil {
		return PushPairing{}, "", err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: tenantID, ActorUserID: &userID, ActorType: "user",
		Action: "mfa.push_pairing_created", ResourceType: "push_pairing", ResourceID: &p.ID,
		IP: ip, UserAgent: ua,
		Metadata: map[string]any{"expires_at": p.ExpiresAt},
	}); err != nil {
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
	p := PushPairing{ID: id}
	var used *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT expires_at, used_at, device_id FROM auth.mfa_push_pairings WHERE id = $1 AND user_id = $2
	`, id, userID).Scan(&p.ExpiresAt, &used, &p.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PushPairing{}, errs.ErrNotFound
	}
	if err != nil {
		return PushPairing{}, err
	}
	switch {
	case used != nil:
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
	var found bool
	err := s.pool.QueryRow(ctx, `
		WITH withdrawn AS (
		    UPDATE auth.mfa_push_pairings SET expires_at = LEAST(expires_at, NOW())
		    WHERE id = $1 AND user_id = $2 AND used_at IS NULL
		    RETURNING id
		)
		SELECT EXISTS (SELECT 1 FROM auth.mfa_push_pairings WHERE id = $1 AND user_id = $2)
	`, id, userID).Scan(&found)
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
	UserID      uuid.UUID  `json:"user_id"`
	Device      PushDevice `json:"device"`
	DeviceToken string     `json:"device_token"`
}

// ClaimPushPairing links the phone presenting code to the account that asked
// for it, as RegisterPushDevice does, and uses the code up. A wrong, used or
// expired code, or one for an inactive account, gets the same
// ErrMFAPairingCodeInvalid. Audited as mfa.push_device_linked.
func (s *Service) ClaimPushPairing(ctx context.Context, code, name, pushToken, platform, ip, ua string) (PushPairingClaim, error) {
	normalized := normalizePairingCode(code)
	if normalized == "" {
		return PushPairingClaim{}, errs.ErrMFAPairingCodeInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushPairingClaim{}, err
	}
	defer tx.Rollback(ctx)
	var pairingID, userID uuid.UUID
	var tenantID *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT p.id, p.user_id, p.tenant_id
		FROM auth.mfa_push_pairings p
		JOIN "user".users u ON u.id = p.user_id
		WHERE p.code_hash = $1 AND p.used_at IS NULL AND p.expires_at > NOW()
		  AND u.status = 'active' AND u.deleted_at IS NULL
		FOR UPDATE OF p
	`, secretHash(normalized)).Scan(&pairingID, &userID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PushPairingClaim{}, errs.ErrMFAPairingCodeInvalid
	}
	if err != nil {
		return PushPairingClaim{}, err
	}
	device, token, err := s.registerPushDeviceTx(ctx, tx, userID, name, pushToken, platform)
	if err != nil {
		return PushPairingClaim{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_push_pairings SET used_at = NOW(), device_id = $2 WHERE id = $1
	`, pairingID, device.ID); err != nil {
		return PushPairingClaim{}, err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: tenantID, ActorUserID: &userID, ActorType: "device",
		Action: "mfa.push_device_linked", ResourceType: "push_device", ResourceID: &device.ID,
		IP: ip, UserAgent: ua,
		Metadata: map[string]any{"pairing_id": pairingID, "platform": device.Platform},
	}); err != nil {
		return PushPairingClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PushPairingClaim{}, err
	}
	return PushPairingClaim{UserID: userID, Device: device, DeviceToken: token}, nil
}

// PurgeExpiredPushPairings deletes pairing codes that expired longer ago than
// retention, used or not, and returns how many. Run on a schedule.
func PurgeExpiredPushPairings(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM auth.mfa_push_pairings WHERE expires_at < $1`,
		time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- HTTP: the signed-in person (authenticated) ---

// createPushPairing → POST /v1/mfa/push/pairing.
func (h *Handler) createPushPairing(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	pairing, code, err := h.Service.CreatePushPairing(r.Context(), *p.UserID, p.TenantID, httpx.ClientIP(r), r.UserAgent())
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
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
	claim, err := h.Service.ClaimPushPairing(r.Context(), in.Code, in.Name, in.PushToken, in.Platform,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, claim)
}
