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
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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

// hookState is an organization's enabled sign-in hooks as last read: whether
// there are any, whether all fail open, and the hook a skip names (the first
// that fails closed, else the first).
type hookState struct {
	present  bool
	id       uuid.UUID
	failOpen bool
}

// stateOf returns the hookState of an organization's enabled hooks.
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

// Run implements authentication.LoginHook: it calls the organization's enabled hooks, oldest first. The first
// deny refuses the sign-in with ErrAuthHookDenied; otherwise it returns the claims to add to the
// access token, a later hook's replacing an earlier one's of the same name. skipped handles a hook
// that gives no answer.
func (s *Service) Run(ctx context.Context, organizationID, userID uuid.UUID, email string) (map[string]any, error) {
	if organizationID == uuid.Nil {
		return nil, nil
	}
	hooks, err := s.q.ListEnabledSignInHooks(ctx, organizationID)
	if err != nil {
		// Whether the organization's hooks fail open can't be read now, so it
		// is taken from the last time they were read here: a fail-closed
		// organization stays fail-closed. Never read, the hooks' default
		// (fail open) applies.
		last, _ := s.known.Load(organizationID)
		state, seen := last.(hookState)
		return s.skipped(ctx, organizationID, userID, state.id, skipUnreadable, !seen || !state.present || state.failOpen, err)
	}
	s.known.Store(organizationID, stateOf(hooks))
	if len(hooks) == 0 {
		return nil, nil
	}
	payload, _ := json.Marshal(map[string]any{
		"trigger":         "post_login",
		"organization_id": organizationID,
		"user_id":         userID,
		"email":           email,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	})
	var claims map[string]any
	for _, hook := range hooks {
		got, err := s.runHook(ctx, organizationID, userID, hook, payload)
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
func (s *Service) runHook(ctx context.Context, organizationID, userID uuid.UUID, hook dbgen.ListEnabledSignInHooksRow, payload []byte) (map[string]any, error) {
	secrets, err := s.secretsOf(organizationID, hook.ID, hook.SecretCt, hook.SecretNonce,
		previousSecret{hook.PreviousSecretCt, hook.PreviousSecretNonce, hook.PreviousSecretExpiresAt})
	if err != nil {
		s.counted(ctx, organizationID, hook.ID, outcomeSkipped, 0)
		return s.skipped(ctx, organizationID, userID, hook.ID, skipSecretUnavailable, hook.FailOpen, err)
	}

	body, status, err := s.call(ctx, hook.Url, secrets, payload)
	if err != nil {
		s.counted(ctx, organizationID, hook.ID, outcomeSkipped, status)
		return s.skipped(ctx, organizationID, userID, hook.ID, skipCallFailed, hook.FailOpen, err)
	}
	if _, ok := parseAnswer(body); !ok {
		s.counted(ctx, organizationID, hook.ID, outcomeSkipped, status)
		return s.skipped(ctx, organizationID, userID, hook.ID, skipUnparseable, hook.FailOpen, errors.New("the hook's answer isn't a JSON object"))
	}
	msg, denied, claims := decide(hook.FailOpen, nil, body)
	if denied {
		s.counted(ctx, organizationID, hook.ID, outcomeDenied, status)
		return nil, errs.ErrAuthHookDenied.WithMessage(msg)
	}
	s.counted(ctx, organizationID, hook.ID, outcomeAllowed, status)
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
func (s *Service) counted(ctx context.Context, organizationID, hookID uuid.UUID, outcome string, status int) {
	var code *int32
	if status > 0 {
		c := int32(status) // #nosec G115 -- an HTTP status
		code = &c
	}
	if err := s.q.RecordHookCall(context.WithoutCancel(ctx), dbgen.RecordHookCallParams{
		Outcome: &outcome, StatusCode: code, ID: hookID, OrganizationID: organizationID,
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
	until     *time.Time
}

// secretsOf is what a hook's calls are signed with: its secret, opened, then
// while it overlaps the one it replaced. A replaced secret that can't be
// opened is left out, with a warning, rather than stop the calls.
func (s *Service) secretsOf(organizationID, hookID uuid.UUID, ct, nonce []byte, previous previousSecret) ([]string, error) {
	current, err := s.box.Open(organizationID, "auth-hook-signing", hookID.String(), ct, nonce)
	if err != nil {
		return nil, err
	}
	secrets := []string{string(current)}
	if len(previous.ct) > 0 && previous.until != nil && time.Now().Before(*previous.until) {
		if plain, err := s.box.Open(organizationID, "auth-hook-signing", hookID.String(), previous.ct, previous.nonce); err == nil {
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
func (s *Service) skipped(ctx context.Context, organizationID, userID, hookID uuid.UUID, reason string, failOpen bool, cause error) (map[string]any, error) {
	outcome := "allowed"
	if !failOpen {
		outcome = "refused"
	}
	hookSkips.WithLabelValues(reason, outcome).Inc()
	slog.Warn("authhook: the sign-in hook gave no answer", "organization_id", organizationID, "hook_id", hookID, "reason", reason, "outcome", outcome, "err", cause)
	// Recorded even when the request is gone, within a short bound. A skip
	// before any hook was read (hookID uuid.Nil) names no hook.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	signingIn := audit.Actor{UserID: &userID, Type: "user"}
	if err := audit.RecordAlone(rctx, s.pool, signingIn.Event(organizationID, "auth_hook.skipped", "auth_hook", hookID,
		map[string]any{"reason": reason, "outcome": outcome, "fail_open": failOpen})); err != nil {
		slog.Warn("authhook: record a skipped hook", "organization_id", organizationID, "reason", reason, "err", err)
	}
	if !failOpen {
		return nil, errs.ErrAuthHookDenied.WithMessage(hookUnavailable)
	}
	return nil, nil
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
