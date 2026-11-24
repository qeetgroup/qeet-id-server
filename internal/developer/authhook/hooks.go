package authhook

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

// Create registers a login hook at url, its signing secret encrypted, recorded
// as actor's, who is noted as its creator. The URL must be an allowed outbound
// destination.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, url, secret string, failOpen bool, actor audit.Actor) (*Hook, error) {
	if _, err := s.egress.ValidateHTTPURL(url); err != nil {
		return nil, ErrURLInvalid
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(organizationID, "auth-hook-signing", id.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateHook(ctx, dbgen.CreateHookParams{
		ID: id, OrganizationID: organizationID, Url: url, SecretCt: ciphertext, SecretNonce: nonce,
		FailOpen: failOpen, CreatedBy: actor.UserID,
	})
	if err != nil {
		return nil, err
	}
	hook := &Hook{
		ID:        row.ID,
		Trigger:   row.Trigger,
		URL:       row.Url,
		Enabled:   row.Enabled,
		FailOpen:  row.FailOpen,
		CreatedAt: row.CreatedAt,
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "auth_hook.created", "auth_hook", hook.ID,
		map[string]any{"url": hook.URL, "fail_open": hook.FailOpen})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: hook.ID, Topic: "auth-hook.events", EventType: "auth_hook.created",
		Payload: map[string]any{"hook_id": hook.ID, "organization_id": organizationID, "url": hook.URL, "fail_open": hook.FailOpen},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return hook, nil
}

// List returns the organization's hooks.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Hook, error) {
	rows, err := s.q.ListHooks(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Hook, 0, len(rows))
	for _, row := range rows {
		h := Hook{
			ID:          row.ID,
			Trigger:     row.Trigger,
			URL:         row.Url,
			Enabled:     row.Enabled,
			FailOpen:    row.FailOpen,
			CreatedAt:   row.CreatedAt,
			LastOutcome: row.LastOutcome,
			Calls:       row.CallCount,
			Skips:       row.SkipCount,
			Denies:      row.DenyCount,
		}
		h.LastCalledAt = row.LastCalledAt
		if row.PreviousSecretExpiresAt != nil && time.Now().Before(*row.PreviousSecretExpiresAt) {
			until := *row.PreviousSecretExpiresAt
			h.PreviousSecretExpiresAt = &until
		}
		if row.LastStatusCode != nil {
			code := int(*row.LastStatusCode)
			h.LastStatusCode = &code
		}
		out = append(out, h)
	}
	return out, nil
}

// HookSettings are a hook's switches, address and signing secret. In an
// update, a nil field keeps its current value.
type HookSettings struct {
	Enabled  *bool   `json:"enabled"`
	FailOpen *bool   `json:"fail_open"`
	URL      *string `json:"url"`
	Secret   *string `json:"secret"`
}

// Update sets whichever of the settings are given on one of the organization's
// hooks, keeping the rest, and returns whether it is now enabled and fails
// open. It is recorded as actor's.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in HookSettings, actor audit.Actor) (enabled, failOpen bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback(ctx)
	if in.URL != nil || in.Secret != nil {
		if err := s.setEndpoint(ctx, tx, id, organizationID, in.URL, in.Secret); err != nil {
			return false, false, err
		}
	}
	row, err := s.q.WithTx(tx).UpdateHook(ctx, dbgen.UpdateHookParams{
		Enabled:        in.Enabled,
		FailOpen:       in.FailOpen,
		ID:             id,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, err
	}
	metadata := map[string]any{"enabled": row.Enabled, "fail_open": row.FailOpen, "secret_changed": in.Secret != nil}
	if in.URL != nil {
		metadata["url"] = *in.URL
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "auth_hook.updated", "auth_hook", id, metadata)); err != nil {
		return false, false, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.updated",
		Payload: map[string]any{"hook_id": id, "organization_id": organizationID, "enabled": row.Enabled, "fail_open": row.FailOpen}}); err != nil {
		return false, false, err
	}
	return row.Enabled, row.FailOpen, tx.Commit(ctx)
}

// setEndpoint gives one of the organization's hooks a new URL, checked as on
// creation, a new signing secret, encrypted, or both, within tx. The secret a
// new one replaces signs beside it for SecretRotationOverlap; replacing it
// again within that ends the older one's at once.
func (s *Service) setEndpoint(ctx context.Context, tx pgx.Tx, id, organizationID uuid.UUID, url, secret *string) error {
	if url != nil {
		if _, err := s.egress.ValidateHTTPURL(*url); err != nil {
			return ErrURLInvalid
		}
	}
	params := dbgen.SetHookEndpointParams{Url: url, ID: id, OrganizationID: organizationID}
	if secret != nil {
		cur, err := s.q.WithTx(tx).LockHookSecret(ctx, dbgen.LockHookSecretParams{ID: id, OrganizationID: organizationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		params.PreviousCt, params.PreviousNonce = cur.SecretCt, cur.SecretNonce
		params.PreviousExpiresAt = new(time.Now().UTC().Add(SecretRotationOverlap))
		ct, nonce, err := s.box.Seal(organizationID, "auth-hook-signing", id.String(), []byte(*secret))
		if err != nil {
			return err
		}
		params.SecretCt, params.SecretNonce = ct, nonce
	}
	n, err := s.q.WithTx(tx).SetHookEndpoint(ctx, params)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TestResult is how a hook answered a test call: the status, how long it took,
// what it decided (allow, deny, or none when it gave no answer) with its
// message and claims, and what went wrong.
type TestResult struct {
	StatusCode int            `json:"status_code"`
	DurationMS int64          `json:"duration_ms"`
	Decision   string         `json:"decision"`
	Message    string         `json:"message,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// Test calls one of the organization's hooks as a sign-in would, with "test": true
// and a placeholder person, and reports how it answered. It doesn't count
// toward the hook's figures. It is recorded as actor's.
func (s *Service) Test(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) (*TestResult, error) {
	hook, err := s.q.GetHookForCall(ctx, dbgen.GetHookForCallParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &TestResult{Decision: "none"}
	secrets, err := s.secretsOf(organizationID, hook.ID, hook.SecretCt, hook.SecretNonce,
		previousSecret{hook.PreviousSecretCt, hook.PreviousSecretNonce, hook.PreviousSecretExpiresAt})
	if err != nil {
		out.Error = "the signing secret can't be read"
	} else {
		payload, _ := json.Marshal(map[string]any{
			"trigger": "post_login", "test": true, "organization_id": organizationID, "user_id": uuid.Nil,
			"email": "test@example.invalid", "timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		started := time.Now()
		body, status, callErr := s.call(ctx, hook.Url, secrets, payload)
		out.StatusCode, out.DurationMS = status, time.Since(started).Milliseconds()
		switch r, ok := parseAnswer(body); {
		case callErr != nil:
			out.Error = callErr.Error()
		case !ok:
			out.Error = "the hook's answer isn't a JSON object"
		case strings.EqualFold(strings.TrimSpace(r.Decision), "deny"):
			out.Decision, out.Message = "deny", r.Message
		default:
			out.Decision, out.Claims = "allow", r.Claims
		}
	}
	if err := audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "auth_hook.tested", "auth_hook", id,
		map[string]any{"status_code": out.StatusCode, "decision": out.Decision, "duration_ms": out.DurationMS})); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes one of the organization's hooks, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteHook(ctx, dbgen.DeleteHookParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "auth_hook.deleted", "auth_hook", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.deleted", Payload: map[string]any{"hook_id": id, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
