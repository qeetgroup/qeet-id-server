package mfa

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// pushDeviceTTL is how long a linked phone's device credential works after it
// was last linked; linking again renews it.
const pushDeviceTTL = 180 * 24 * time.Hour

// RegisterPushDevice upserts a device push token and returns the device record
// plus a one-time device_token the app must persist for future challenge-respond
// calls. On re-registration of the same push_token the device_token is rotated.
func (s *Service) RegisterPushDevice(ctx context.Context, userID uuid.UUID, name, pushToken, platform string) (PushDevice, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushDevice{}, "", err
	}
	defer tx.Rollback(ctx)
	d, tok, err := s.registerPushDeviceTx(ctx, tx, userID, name, pushToken, platform)
	if err != nil {
		return PushDevice{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return PushDevice{}, "", err
	}
	return d, tok, nil
}

// registerPushDeviceTx is RegisterPushDevice inside the caller's transaction.
func (s *Service) registerPushDeviceTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, name, pushToken, platform string) (PushDevice, string, error) {
	tok, err := randomHex(32)
	if err != nil {
		return PushDevice{}, "", err
	}
	if s.box == nil {
		return PushDevice{}, "", errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
	pushTokenHash := secretHash(pushToken)
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-push-token", pushTokenHash, []byte(pushToken))
	if err != nil {
		return PushDevice{}, "", err
	}
	row, err := s.q.WithTx(tx).UpsertPushDevice(ctx, dbgen.UpsertPushDeviceParams{
		UserID: userID, Name: name, PushTokenCt: ciphertext, PushTokenNonce: nonce, PushTokenHash: pushTokenHash,
		Platform: platform, DeviceTokenHash: secretHash(tok), TtlSeconds: pushDeviceTTL.Seconds(),
	})
	if err != nil {
		return PushDevice{}, "", err
	}
	d := PushDevice{
		ID:         row.ID,
		Name:       row.Name,
		Platform:   row.Platform,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
	}
	return d, tok, nil
}

// ListPushDevices returns the user's paired phones.
func (s *Service) ListPushDevices(ctx context.Context, userID uuid.UUID) ([]PushDevice, error) {
	rows, err := s.q.ListPushDevices(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PushDevice, 0, len(rows))
	for _, r := range rows {
		out = append(out, PushDevice{
			ID:         r.ID,
			Name:       r.Name,
			Platform:   r.Platform,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
		})
	}
	return out, nil
}

// RevokePushDevice unpairs one of the user's phones.
func (s *Service) RevokePushDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	n, err := s.q.DeletePushDevice(ctx, dbgen.DeletePushDeviceParams{ID: deviceID, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrPushDeviceNotFound
	}
	return nil
}

type registerPushDeviceInput struct {
	Name      string `json:"name"`
	PushToken string `json:"push_token"`
	Platform  string `json:"platform"`
}

func (h *Handler) listPushDevices(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	devices, err := h.Service.ListPushDevices(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(devices))
}

func (h *Handler) registerPushDevice(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in registerPushDeviceInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.PushToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("push_token required"))
		return
	}
	if in.Platform != "ios" && in.Platform != "android" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("platform must be ios or android"))
		return
	}
	device, deviceToken, err := h.Service.RegisterPushDevice(r.Context(), *p.UserID, in.Name, in.PushToken, in.Platform)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellPhoneLinked(r.Context(), *p.UserID)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"device":       device,
		"device_token": deviceToken,
		"warning":      "store device_token securely; it will not be shown again",
	})
}

func (h *Handler) revokePushDevice(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	deviceID, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx, by := r.Context(), audit.ActorOf(r)
	if err := h.Service.RevokePushDevice(ctx, *p.UserID, deviceID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.auditPushDevice(ctx, by, p.OrganizationID, *p.UserID, deviceID, "mfa.push_device_revoked")
	h.Service.tellPhoneUnlinked(r.Context(), *p.UserID)
	w.WriteHeader(http.StatusNoContent)
}

type unlinkPushDeviceInput struct {
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
}

// unlinkPushDevice → POST /v1/mfa/push/devices/{id}/unlink: a phone removes
// itself, proving it is that device with the credential it was given when
// linked (even one past its expiry: removing itself grants nothing).
func (h *Handler) unlinkPushDevice(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in unlinkPushDeviceInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DeviceToken == "" || in.UserID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_id and device_token required"))
		return
	}
	n, err := h.Service.q.DeletePushDeviceByCredential(r.Context(), dbgen.DeletePushDeviceByCredentialParams{
		ID: id, UserID: in.UserID, DeviceTokenHash: secretHash(in.DeviceToken),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if n == 0 {
		httpx.WriteError(w, r, ErrPushUnauthorized)
		return
	}
	// The phone removes itself, with no signed-in principal: it is the actor.
	ctx, phone := r.Context(), as(audit.ActorOf(r), "device", in.UserID)
	h.Service.auditPushDevice(ctx, phone, nil, in.UserID, id, "mfa.push_device_unlinked")
	h.Service.tellPhoneUnlinked(r.Context(), in.UserID)
	w.WriteHeader(http.StatusNoContent)
}

type updatePushTokenInput struct {
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
	PushToken   string    `json:"push_token"`
}

// maxPushTokenLength bounds a push token: APNs tokens are 64 hex characters and FCM
// registration tokens a few hundred.
const maxPushTokenLength = 4096

// updatePushToken → POST /v1/mfa/push/devices/{id}/push-token: a linked phone replaces the
// push token its platform rotated, proving it is that device with its current (unexpired)
// device credential. The credential, the link's expiry and the platform are unchanged.
func (h *Handler) updatePushToken(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in updatePushTokenInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DeviceToken == "" || in.UserID == uuid.Nil || in.PushToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_id, device_token and push_token required"))
		return
	}
	if len(in.PushToken) > maxPushTokenLength {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("push_token is too long"))
		return
	}
	if err := h.Service.UpdatePushToken(r.Context(), id, in.UserID, in.DeviceToken, in.PushToken); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdatePushToken stores a phone's new push token, sealed like the one it replaces. The phone
// proves itself with its device credential, which must not have expired. Another of the
// user's links already holding the same token (the same app, linked before) is removed, so the
// phone is sent each request once. ErrMFAPushUnauthorized when the device or credential does
// not match.
func (s *Service) UpdatePushToken(ctx context.Context, deviceID, userID uuid.UUID, deviceToken, pushToken string) error {
	if s.box == nil {
		return errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	_, err = q.LockLinkedPushDevice(ctx, dbgen.LockLinkedPushDeviceParams{ID: deviceID, UserID: userID, DeviceTokenHash: secretHash(deviceToken)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPushUnauthorized
	}
	if err != nil {
		return err
	}
	pushTokenHash := secretHash(pushToken)
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-push-token", pushTokenHash, []byte(pushToken))
	if err != nil {
		return err
	}
	if err := q.DeleteOtherPushDevicesWithToken(ctx, dbgen.DeleteOtherPushDevicesWithTokenParams{
		UserID: userID, PushTokenHash: pushTokenHash, ID: deviceID,
	}); err != nil {
		return err
	}
	if err := q.SetPushDeviceToken(ctx, dbgen.SetPushDeviceTokenParams{
		ID: deviceID, PushTokenCt: ciphertext, PushTokenNonce: nonce, PushTokenHash: pushTokenHash,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// auditPushDevice records owner's linked phone deviceID removed by by, in
// organizationID's trail (nil: none), best effort: the removal stands either
// way.
func (s *Service) auditPushDevice(ctx context.Context, by audit.Actor, organizationID *uuid.UUID, owner, deviceID uuid.UUID, action string) {
	_ = audit.RecordAlone(ctx, s.pool, by.EventIn(organizationID, action, "push_device", deviceID, map[string]any{"user_id": owner}))
}
