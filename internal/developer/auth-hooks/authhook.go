// Package authhook runs an organisation's synchronous sign-in hooks: after the
// credentials check, Run POSTs a signed event to each enabled hook's URL, which
// answers allow or deny. When a hook gives no answer, its fail_open decides
// (allow by default, so an outage never locks everyone out) and the skip is
// recorded.
package authhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const hookTimeout = 3 * time.Second

// hookUnavailable is what a sign-in is told when a fail-closed hook gave no
// answer.
const hookUnavailable = "Sign-in is temporarily unavailable. Please try again later."

// Why a hook gave no answer.
const (
	skipUnreadable        = "unreadable"         // the hook couldn't be read
	skipSecretUnavailable = "secret_unavailable" // its signing secret couldn't be opened
	skipCallFailed        = "call_failed"        // the call errored, timed out or wasn't 2xx
	skipUnparseable       = "unparseable"        // the answer couldn't be read
)

var hookSkips = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "auth_hook_skipped_total",
	Help: "Sign-in hook evaluations that got no answer from the hook, by reason (unreadable, secret_unavailable, call_failed, unparseable) and outcome (allowed where the hook fails open, refused where it fails closed).",
}, []string{"reason", "outcome"})

func init() {
	// Publish every series at zero so an alert can rate() it from the start.
	for _, reason := range []string{skipUnreadable, skipSecretUnavailable, skipCallFailed, skipUnparseable} {
		for _, outcome := range []string{"allowed", "refused"} {
			hookSkips.WithLabelValues(reason, outcome)
		}
	}
}

// hookState is an organisation's enabled sign-in hooks as last read: whether
// there are any, whether all fail open, and the hook a skip names (the first
// that fails closed, else the first).
type hookState struct {
	present  bool
	id       uuid.UUID
	failOpen bool
}

// stateOf returns the hookState of an organisation's enabled hooks.
func stateOf(hooks []dbgen.ListEnabledSignInHooksRow) hookState {
	if len(hooks) == 0 {
		return hookState{}
	}
	for _, h := range hooks {
		if !h.FailOpen {
			return hookState{present: true, id: h.ID}
		}
	}
	return hookState{present: true, id: hooks[0].ID, failOpen: true}
}

// Hook is a tenant's login hook, without its signing secret. LastOutcome is
// how its last sign-in call ended: allowed, denied or skipped (no answer).
// PreviousSecretExpiresAt is when a replaced secret stops signing its calls
// beside the new one (nil: none does).
type Hook struct {
	ID                      uuid.UUID  `json:"id"`
	Trigger                 string     `json:"trigger"`
	URL                     string     `json:"url"`
	Enabled                 bool       `json:"enabled"`
	FailOpen                bool       `json:"fail_open"`
	CreatedAt               time.Time  `json:"created_at"`
	LastCalledAt            *time.Time `json:"last_called_at"`
	LastOutcome             *string    `json:"last_outcome"`
	LastStatusCode          *int       `json:"last_status_code"`
	Calls                   int64      `json:"calls"`
	Skips                   int64      `json:"skips"`
	Denies                  int64      `json:"denies"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at"`
}

// Service manages and runs sign-in hooks. known holds each organisation's hooks
// as last read (uuid.UUID → hookState), for a sign-in made while they can't be
// read.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	client *http.Client
	egress *egress.Policy
	box    *envelope.Cipher
	known  sync.Map
}

// NewService returns the login hook service.
func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{pool: pool, q: dbgen.New(pool), client: policy.HTTPClient(hookTimeout), egress: policy}
}

// SetCipher sets the cipher that encrypts login hook secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// Run implements auth.LoginHook. It calls each of the organisation's enabled
// hooks, oldest first. The first to deny refuses the sign-in with
// ErrAuthHookDenied; otherwise Run returns the claims they asked to add to the
// access token, a later hook's replacing an earlier one's of the same name.
// A hook that gives no answer is handled by skipped.
func (s *Service) Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error) {
	if tenantID == uuid.Nil {
		return nil, nil
	}
	hooks, err := s.q.ListEnabledSignInHooks(ctx, tenantID)
	if err != nil {
		// Whether the organisation's hooks fail open can't be read now, so it
		// is taken from the last time they were read here: a fail-closed
		// organisation stays fail-closed. Never read, the hooks' default
		// (fail open) applies.
		last, _ := s.known.Load(tenantID)
		state, seen := last.(hookState)
		return s.skipped(ctx, tenantID, userID, state.id, skipUnreadable, !seen || !state.present || state.failOpen, err)
	}
	s.known.Store(tenantID, stateOf(hooks))
	if len(hooks) == 0 {
		return nil, nil
	}
	payload, _ := json.Marshal(map[string]any{
		"trigger":   "post_login",
		"tenant_id": tenantID,
		"user_id":   userID,
		"email":     email,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	var claims map[string]any
	for _, hook := range hooks {
		got, err := s.runHook(ctx, tenantID, userID, hook, payload)
		if err != nil {
			return nil, err
		}
		for name, value := range got {
			if claims == nil {
				claims = map[string]any{}
			}
			claims[name] = value
		}
	}
	return claims, nil
}

// runHook calls one hook with payload, signed with its secrets, and returns
// the claims it asked for, ErrAuthHookDenied when it denies, or skipped's
// answer when it gives none.
func (s *Service) runHook(ctx context.Context, tenantID, userID uuid.UUID, hook dbgen.ListEnabledSignInHooksRow, payload []byte) (map[string]any, error) {
	secrets, err := s.secretsOf(tenantID, hook.ID, hook.SecretCt, hook.SecretNonce,
		previousSecret{hook.PreviousSecretCt, hook.PreviousSecretNonce, hook.PreviousSecretExpiresAt})
	if err != nil {
		s.counted(ctx, tenantID, hook.ID, outcomeSkipped, 0)
		return s.skipped(ctx, tenantID, userID, hook.ID, skipSecretUnavailable, hook.FailOpen, err)
	}

	body, status, err := s.call(ctx, hook.Url, secrets, payload)
	if err != nil {
		s.counted(ctx, tenantID, hook.ID, outcomeSkipped, status)
		return s.skipped(ctx, tenantID, userID, hook.ID, skipCallFailed, hook.FailOpen, err)
	}
	if _, ok := parseAnswer(body); !ok {
		s.counted(ctx, tenantID, hook.ID, outcomeSkipped, status)
		return s.skipped(ctx, tenantID, userID, hook.ID, skipUnparseable, hook.FailOpen, errors.New("the hook's answer isn't a JSON object"))
	}
	msg, denied, claims := decide(hook.FailOpen, nil, body)
	if denied {
		s.counted(ctx, tenantID, hook.ID, outcomeDenied, status)
		return nil, errs.ErrAuthHookDenied.WithMessage(msg)
	}
	s.counted(ctx, tenantID, hook.ID, outcomeAllowed, status)
	return claims, nil
}

// How a hook's call ended, as its figures count it.
const (
	outcomeAllowed = "allowed"
	outcomeDenied  = "denied"
	outcomeSkipped = "skipped"
)

// counted adds one call to the hook's figures. Losing it costs the figures
// only, so it is logged, not returned.
func (s *Service) counted(ctx context.Context, tenantID, hookID uuid.UUID, outcome string, status int) {
	var code *int32
	if status > 0 {
		c := int32(status) // #nosec G115 -- an HTTP status
		code = &c
	}
	if err := s.q.RecordHookCall(context.WithoutCancel(ctx), dbgen.RecordHookCallParams{
		Outcome: &outcome, StatusCode: code, ID: hookID, TenantID: tenantID,
	}); err != nil {
		slog.Warn("authhook: count a call", "hook_id", hookID, "err", err)
	}
}

// SecretRotationOverlap is how long a hook's replaced secret goes on signing
// its calls beside the new one, as for webhooks.
const SecretRotationOverlap = 24 * time.Hour

// previousSecret is a hook's replaced secret, sealed, and when it stops signing.
type previousSecret struct {
	ct, nonce []byte
	until     pgtype.Timestamptz
}

// secretsOf is what a hook's calls are signed with: its secret, opened, then
// while it overlaps the one it replaced. A replaced secret that can't be
// opened is left out, with a warning, rather than stop the calls.
func (s *Service) secretsOf(tenantID, hookID uuid.UUID, ct, nonce []byte, previous previousSecret) ([]string, error) {
	if s.box == nil {
		return nil, errors.New("no cipher to open the signing secret")
	}
	current, err := s.box.Open(tenantID, "auth-hook-signing", hookID.String(), ct, nonce)
	if err != nil {
		return nil, err
	}
	secrets := []string{string(current)}
	if len(previous.ct) > 0 && previous.until.Valid && time.Now().Before(previous.until.Time) {
		if plain, err := s.box.Open(tenantID, "auth-hook-signing", hookID.String(), previous.ct, previous.nonce); err == nil {
			secrets = append(secrets, string(plain))
		} else {
			slog.Warn("authhook: replaced secret unreadable; signing with the current one only", "hook_id", hookID, "err", err)
		}
	}
	return secrets, nil
}

// skipped answers a sign-in the hook gave no answer for, refusing it with
// hookUnavailable unless failOpen, and records the skip (an auth_hook.skipped
// audit event and the auth_hook_skipped_total metric) so an alert can fire.
func (s *Service) skipped(ctx context.Context, tenantID, userID, hookID uuid.UUID, reason string, failOpen bool, cause error) (map[string]any, error) {
	outcome := "allowed"
	if !failOpen {
		outcome = "refused"
	}
	hookSkips.WithLabelValues(reason, outcome).Inc()
	slog.Warn("authhook: the sign-in hook gave no answer", "tenant_id", tenantID, "hook_id", hookID, "reason", reason, "outcome", outcome, "err", cause)
	var resource *uuid.UUID
	if hookID != uuid.Nil {
		resource = &hookID
	}
	// Recorded even when the request is gone, within a short bound.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.record(rctx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "user",
		Action: "auth_hook.skipped", ResourceType: "auth_hook", ResourceID: resource,
		Metadata: map[string]any{"reason": reason, "outcome": outcome, "fail_open": failOpen},
	}); err != nil {
		slog.Warn("authhook: record a skipped hook", "tenant_id", tenantID, "reason", reason, "err", err)
	}
	if !failOpen {
		return nil, errs.ErrAuthHookDenied.WithMessage(hookUnavailable)
	}
	return nil, nil
}

// record writes one audit event in its own transaction.
func (s *Service) record(ctx context.Context, e audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// answer is what a hook said.
type answer struct {
	Decision string         `json:"decision"`
	Message  string         `json:"message"`
	Claims   map[string]any `json:"claims"`
}

// parseAnswer reads a hook's answer; ok is false when it can't be read.
func parseAnswer(body []byte) (answer, bool) {
	var r answer
	if err := json.Unmarshal(body, &r); err != nil {
		return answer{}, false
	}
	return r, true
}

// call POSTs payload signed with secrets as webhook deliveries are
// (requestsig: a timestamp, and a signature for each), returning the response
// body, its status (0 when there was none) and a non-nil error on transport
// failure, timeout, or a non-2xx status.
func (s *Service) call(ctx context.Context, url string, secrets []string, payload []byte) ([]byte, int, error) {
	cctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	requestsig.SetHeaders(req.Header, time.Now(), payload, secrets...)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return b, resp.StatusCode, errors.New("hook returned non-2xx")
	}
	return b, resp.StatusCode, nil
}

// decide turns a hook call's outcome into a deny message, or an allow with the
// hook's custom claims. It denies on decision "deny" and, unless failOpen, when
// the call failed or the body can't be parsed: a 2xx with an unreadable body
// has said nothing, so it must not get past a fail-closed hook.
func decide(failOpen bool, callErr error, body []byte) (denyMsg string, denied bool, claims map[string]any) {
	if callErr != nil {
		if failOpen {
			return "", false, nil
		}
		return hookUnavailable, true, nil
	}
	r, ok := parseAnswer(body)
	if !ok {
		if failOpen {
			return "", false, nil
		}
		return hookUnavailable, true, nil
	}
	if strings.EqualFold(strings.TrimSpace(r.Decision), "deny") {
		msg := strings.TrimSpace(r.Message)
		if msg == "" {
			msg = "Sign-in was blocked by your organization's policy."
		}
		return msg, true, nil
	}
	return "", false, r.Claims
}

// Create registers a login hook at url, its signing secret encrypted, recorded
// as actor's. The URL must be an allowed outbound destination.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, url, secret string, failOpen bool, actor audit.Actor) (*Hook, error) {
	if _, err := s.egress.ValidateHTTPURL(url); err != nil {
		return nil, errs.ErrAuthHookURLInvalid
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("auth-hook secret encryption is unavailable")
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(tenantID, "auth-hook-signing", id.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	var row struct {
		ID        uuid.UUID
		Trigger   string
		URL       string
		Enabled   bool
		FailOpen  bool
		CreatedAt time.Time
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.auth_hooks
		    (id, tenant_id, url, secret_ct, secret_nonce, fail_open, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7::uuid, '00000000-0000-0000-0000-000000000000'))
		RETURNING id, trigger, url, enabled, fail_open, created_at
	`, id, tenantID, url, ciphertext, nonce, failOpen, httpx.PrincipalUserID(ctx)).Scan(
		&row.ID, &row.Trigger, &row.URL, &row.Enabled, &row.FailOpen, &row.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	hook := &Hook{
		ID:        row.ID,
		Trigger:   row.Trigger,
		URL:       row.URL,
		Enabled:   row.Enabled,
		FailOpen:  row.FailOpen,
		CreatedAt: row.CreatedAt,
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.created", "auth_hook", hook.ID,
		map[string]any{"url": hook.URL, "fail_open": hook.FailOpen})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: hook.ID, Topic: "auth-hook.events", EventType: "auth_hook.created",
		Payload: map[string]any{"hook_id": hook.ID, "tenant_id": tenantID, "url": hook.URL, "fail_open": hook.FailOpen},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return hook, nil
}

// List returns the tenant's hooks.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Hook, error) {
	rows, err := s.q.ListHooks(ctx, tenantID)
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
		if row.LastCalledAt.Valid {
			at := row.LastCalledAt.Time
			h.LastCalledAt = &at
		}
		if row.PreviousSecretExpiresAt.Valid && time.Now().Before(row.PreviousSecretExpiresAt.Time) {
			until := row.PreviousSecretExpiresAt.Time
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

// Update sets whichever of the settings are given on one of the tenant's
// hooks, keeping the rest, and returns whether it is now enabled and fails
// open. It is recorded as actor's.
func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, in HookSettings, actor audit.Actor) (enabled, failOpen bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback(ctx)
	if in.URL != nil || in.Secret != nil {
		if err := s.setEndpoint(ctx, tx, id, tenantID, in.URL, in.Secret); err != nil {
			return false, false, err
		}
	}
	row, err := s.q.WithTx(tx).UpdateHook(ctx, dbgen.UpdateHookParams{
		Enabled:  in.Enabled,
		FailOpen: in.FailOpen,
		ID:       id,
		TenantID: tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, errs.ErrAuthHookNotFound
	}
	if err != nil {
		return false, false, err
	}
	metadata := map[string]any{"enabled": row.Enabled, "fail_open": row.FailOpen, "secret_changed": in.Secret != nil}
	if in.URL != nil {
		metadata["url"] = *in.URL
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.updated", "auth_hook", id, metadata)); err != nil {
		return false, false, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.updated",
		Payload: map[string]any{"hook_id": id, "tenant_id": tenantID, "enabled": row.Enabled, "fail_open": row.FailOpen}}); err != nil {
		return false, false, err
	}
	return row.Enabled, row.FailOpen, tx.Commit(ctx)
}

// setEndpoint gives one of the tenant's hooks a new URL, checked as on
// creation, a new signing secret, encrypted, or both, within tx. The secret a
// new one replaces signs beside it for SecretRotationOverlap; replacing it
// again within that ends the older one's at once.
func (s *Service) setEndpoint(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, url, secret *string) error {
	if url != nil {
		if _, err := s.egress.ValidateHTTPURL(*url); err != nil {
			return errs.ErrAuthHookURLInvalid
		}
	}
	params := dbgen.SetHookEndpointParams{Url: url, ID: id, TenantID: tenantID}
	if secret != nil {
		if s.box == nil {
			return errs.ErrInternalServer.WithDetail("auth-hook secret encryption is unavailable")
		}
		cur, err := s.q.WithTx(tx).LockHookSecret(ctx, dbgen.LockHookSecretParams{ID: id, TenantID: tenantID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrAuthHookNotFound
		}
		if err != nil {
			return err
		}
		params.PreviousCt, params.PreviousNonce = cur.SecretCt, cur.SecretNonce
		params.PreviousExpiresAt = pgtype.Timestamptz{Time: time.Now().UTC().Add(SecretRotationOverlap), Valid: true}
		ct, nonce, err := s.box.Seal(tenantID, "auth-hook-signing", id.String(), []byte(*secret))
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
		return errs.ErrAuthHookNotFound
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

// Test calls one of the tenant's hooks as a sign-in would, with "test": true
// and a placeholder person, and reports how it answered. It doesn't count
// toward the hook's figures. It is recorded as actor's.
func (s *Service) Test(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) (*TestResult, error) {
	hook, err := s.q.GetHookForCall(ctx, dbgen.GetHookForCallParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAuthHookNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &TestResult{Decision: "none"}
	secrets, err := s.secretsOf(tenantID, hook.ID, hook.SecretCt, hook.SecretNonce,
		previousSecret{hook.PreviousSecretCt, hook.PreviousSecretNonce, hook.PreviousSecretExpiresAt})
	if err != nil {
		out.Error = "the signing secret can't be read"
	} else {
		payload, _ := json.Marshal(map[string]any{
			"trigger": "post_login", "test": true, "tenant_id": tenantID, "user_id": uuid.Nil,
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.tested", "auth_hook", id,
		map[string]any{"status_code": out.StatusCode, "decision": out.Decision, "duration_ms": out.DurationMS})); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// Delete removes one of the tenant's hooks, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteHook(ctx, dbgen.DeleteHookParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAuthHookNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.deleted", "auth_hook", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.deleted", Payload: map[string]any{"hook_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Handler serves the login hook HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the login hook routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/auth-hooks", h.list)
	r.Post("/tenants/{tenantID}/auth-hooks", h.create)
	r.Patch("/tenants/{tenantID}/auth-hooks/{id}", h.patch)
	r.Post("/tenants/{tenantID}/auth-hooks/{id}/test", h.test)
	r.Delete("/tenants/{tenantID}/auth-hooks/{id}", h.del)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrAuthHookInvalidID, errs.ErrAuthHookTenantMismatch)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		URL      string `json:"url"`
		Secret   string `json:"secret"`
		FailOpen *bool  `json:"fail_open"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	failOpen := true
	if in.FailOpen != nil {
		failOpen = *in.FailOpen
	}
	hook, err := h.Service.Create(r.Context(), tenantID, in.URL, in.Secret, failOpen, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, hook)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAuthHookInvalidID)
		return
	}
	var in HookSettings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	enabled, failOpen, err := h.Service.Update(r.Context(), id, tenantID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "fail_open": failOpen})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAuthHookInvalidID)
		return
	}
	if err := h.Service.Delete(r.Context(), id, tenantID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// test handles POST /v1/tenants/{tenantID}/auth-hooks/{id}/test.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAuthHookInvalidID)
		return
	}
	out, err := h.Service.Test(r.Context(), id, tenantID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
