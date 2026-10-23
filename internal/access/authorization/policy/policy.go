// Package policy stores per-tenant security policy. Which addresses may sign
// in is not part of it: that is the address rules (internal/access/risk/ipallow).
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/dbutil"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Policy is a tenant's security policy. Session and step-up settings left
// zero on update take the defaults; session settings apply to sessions opened
// after they are set.
type Policy struct {
	TenantID           uuid.UUID `json:"tenant_id"`
	PasswordMinLength  int       `json:"password_min_length"`
	PasswordComplexity string    `json:"password_complexity"`

	// A session ends SessionMaxAge after sign-in however active, which also
	// bounds an application's grant, or after SessionIdleTimeout unrenewed.
	SessionMaxAge      Duration `json:"session_max_age"`
	SessionIdleTimeout Duration `json:"session_idle_timeout"`

	// MaxSessions caps one person's live sessions here (nil: no limit). At the
	// cap a sign-in ends their least recently used one ("evict_oldest"; its
	// access tokens last out their short TTL) or is refused ("refuse").
	MaxSessions        *int   `json:"max_sessions"`
	SessionLimitAction string `json:"session_limit_action"`

	// Who must sign in with a second factor: "optional", "required" or
	// "admin_only" (holders of a write permission). Existing accounts may defer
	// setup MFAGraceDays (0–90) past MFAEnforcedSince, which is read-only.
	MFAEnforcement   string     `json:"mfa_enforcement"`
	MFAGraceDays     int        `json:"mfa_grace_days"`
	MFAEnforcedSince *time.Time `json:"mfa_enforced_since"`

	// A step-up lasts StepUpWindow (1m–60m, default 5m); StepUpMethods are the
	// factor types that count (empty: all).
	StepUpWindow  Duration       `json:"step_up_window"`
	StepUpMethods []string       `json:"step_up_methods"`
	Settings      map[string]any `json:"settings"`
}

// Duration is a time.Duration written to JSON as a duration string ("720h",
// "30m"), the form the console edits. It also reads a number of nanoseconds.
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	v := time.Duration(d)
	switch {
	case v != 0 && v%time.Hour == 0:
		return json.Marshal(fmt.Sprintf("%dh", v/time.Hour))
	case v != 0 && v%time.Minute == 0:
		return json.Marshal(fmt.Sprintf("%dm", v/time.Minute))
	}
	return json.Marshal(v.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: write it like \"720h\" or \"30m\"", s)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New(`a duration is a string like "720h" or "30m"`)
	}
	*d = Duration(n)
	return nil
}

// The values the enumerated settings may take.
var (
	passwordComplexities = map[string]bool{"relaxed": true, "standard": true, "strict": true}
	sessionLimitActions  = map[string]bool{"evict_oldest": true, "refuse": true}
	mfaEnforcements      = map[string]bool{"optional": true, "required": true, "admin_only": true}
	stepUpMethods        = map[string]bool{"totp": true, "recovery_code": true, "otp": true, "webauthn": true, "push": true}
)

// The bounds of a step-up window, and the window of an organisation that sets
// none (the column default).
const (
	stepUpWindowMin     = time.Minute
	stepUpWindowMax     = time.Hour
	stepUpWindowDefault = 5 * time.Minute
)

// Repository stores security policies. sessionMaxAge and sessionIdle are the
// session bounds of an organisation that sets none (SESSION_MAX_AGE and
// SESSION_IDLE_TIMEOUT, via SetSessionDefaults).
type Repository struct {
	pool          *pgxpool.Pool
	sessionMaxAge time.Duration
	sessionIdle   time.Duration
}

// NewRepository returns a Repository over pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, sessionMaxAge: 30 * 24 * time.Hour, sessionIdle: 24 * time.Hour}
}

// SetSessionDefaults sets the session bounds reported for an organisation that
// has not set its own, and stored for one that saves its policy without them.
func (r *Repository) SetSessionDefaults(maxAge, idle time.Duration) {
	r.sessionMaxAge, r.sessionIdle = maxAge, idle
}

// normalize fills what an update left zero (the platform session bounds, with
// the idle timeout capped at the maximum age, and the default step-up window)
// and reports the fields that are out of range.
func (r *Repository) normalize(p *Policy) []errs.FieldError {
	if p.SessionLimitAction == "" {
		p.SessionLimitAction = "evict_oldest"
	}
	if p.SessionMaxAge == 0 {
		p.SessionMaxAge = Duration(r.sessionMaxAge)
	}
	if p.SessionIdleTimeout == 0 {
		p.SessionIdleTimeout = Duration(min(r.sessionIdle, time.Duration(p.SessionMaxAge)))
	}
	if p.StepUpWindow == 0 {
		p.StepUpWindow = Duration(stepUpWindowDefault)
	}
	if len(p.StepUpMethods) == 0 {
		p.StepUpMethods = nil
	}
	var bad []errs.FieldError
	field := func(name, msg string) {
		bad = append(bad, errs.FieldError{Field: name, Code: "out_of_range", Message: msg})
	}
	maxAge, idle := time.Duration(p.SessionMaxAge), time.Duration(p.SessionIdleTimeout)
	if maxAge < config.SessionMaxAgeMin || maxAge > config.SessionMaxAgeMax {
		field("session_max_age", "Set the maximum session age between 1h and 8760h (one year).")
	}
	if idle < config.SessionIdleTimeoutMin || idle > maxAge {
		field("session_idle_timeout", "Set the idle timeout to at least 15m and no longer than the maximum session age.")
	}
	if p.PasswordMinLength < 8 || p.PasswordMinLength > 128 {
		field("password_min_length", "Set the minimum password length between 8 and 128.")
	}
	if !passwordComplexities[p.PasswordComplexity] {
		field("password_complexity", "Choose relaxed, standard or strict.")
	}
	if !mfaEnforcements[p.MFAEnforcement] {
		field("mfa_enforcement", "Choose optional, required or admin_only.")
	}
	if p.MFAGraceDays < 0 || p.MFAGraceDays > 90 {
		field("mfa_grace_days", "Set the grace period between 0 and 90 days.")
	}
	if p.MaxSessions != nil && (*p.MaxSessions < 1 || *p.MaxSessions > 1000) {
		field("max_sessions", "Set the session limit between 1 and 1000, or leave it empty for no limit.")
	}
	if !sessionLimitActions[p.SessionLimitAction] {
		field("session_limit_action", "Choose evict_oldest or refuse.")
	}
	if w := time.Duration(p.StepUpWindow); w < stepUpWindowMin || w > stepUpWindowMax {
		field("step_up_window", "Set the step-up window between 1m and 60m.")
	}
	seen := map[string]bool{}
	for _, m := range p.StepUpMethods {
		if !stepUpMethods[m] || seen[m] {
			field("step_up_methods", "List each of totp, recovery_code, otp, webauthn and push at most once, or leave it empty for all of them.")
			break
		}
		seen[m] = true
	}
	return bad
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// Get returns the tenant's security policy, or the defaults when it has none.
func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	var p Policy
	var settings []byte
	var sessionAge, sessionIdle, stepUpWindow int64
	err := r.pool.QueryRow(ctx, `
		SELECT tenant_id,
		       password_min_length, password_complexity,
		       EXTRACT(EPOCH FROM session_max_age)::bigint,
		       EXTRACT(EPOCH FROM session_idle_timeout)::bigint,
		       max_sessions, session_limit_action,
		       mfa_enforcement, mfa_grace_days, mfa_enforced_since,
		       EXTRACT(EPOCH FROM step_up_window)::bigint, step_up_methods, settings
		FROM tenant.security_policies WHERE tenant_id = $1
	`, tenantID).Scan(&p.TenantID, &p.PasswordMinLength,
		&p.PasswordComplexity, &sessionAge, &sessionIdle, &p.MaxSessions, &p.SessionLimitAction, &p.MFAEnforcement,
		&p.MFAGraceDays, &p.MFAEnforcedSince, &stepUpWindow, &p.StepUpMethods, &settings)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Policy{
			TenantID:           tenantID,
			PasswordMinLength:  8,
			PasswordComplexity: "standard",
			SessionMaxAge:      Duration(r.sessionMaxAge),
			SessionIdleTimeout: Duration(r.sessionIdle),
			SessionLimitAction: "evict_oldest",
			MFAEnforcement:     "optional",
			StepUpWindow:       Duration(stepUpWindowDefault),
			Settings:           map[string]any{},
		}, nil
	}
	if err != nil {
		return nil, err
	}
	p.SessionMaxAge = Duration(time.Duration(sessionAge) * time.Second)
	p.SessionIdleTimeout = Duration(time.Duration(sessionIdle) * time.Second)
	p.StepUpWindow = Duration(time.Duration(stepUpWindow) * time.Second)
	p.Settings = dbutil.Metadata(settings)
	return &p, nil
}

// Upsert stores the policy and returns when its MFA requirement was turned on
// (nil while optional): the moment it changes from optional, kept while it
// stays on — moving between required and admin_only does not restart a grace
// period.
func (r *Repository) Upsert(ctx context.Context, tx pgx.Tx, p Policy) (*time.Time, error) {
	settings, _ := json.Marshal(p.Settings)
	stepUpWindow := time.Duration(p.StepUpWindow)
	if stepUpWindow == 0 {
		stepUpWindow = stepUpWindowDefault
	}
	var enforcedSince *time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO tenant.security_policies (
			tenant_id,
			password_min_length, password_complexity,
			session_max_age, session_idle_timeout, mfa_enforcement, settings,
			max_sessions, session_limit_action, mfa_grace_days, mfa_enforced_since,
			step_up_window, step_up_methods
		) VALUES ($1, $2, $3, make_interval(secs => $4::bigint),
		         make_interval(secs => $5::bigint), $6,
		         COALESCE(NULLIF($7::jsonb,'null'::jsonb), '{}'::jsonb), $8, COALESCE(NULLIF($9, ''), 'evict_oldest'),
		         $10, CASE WHEN $6 = 'optional' THEN NULL ELSE NOW() END,
		         make_interval(secs => $11::bigint), $12::text[])
		ON CONFLICT (tenant_id) DO UPDATE SET
			password_min_length = EXCLUDED.password_min_length,
			password_complexity = EXCLUDED.password_complexity,
			session_max_age = EXCLUDED.session_max_age,
			session_idle_timeout = EXCLUDED.session_idle_timeout,
			max_sessions = EXCLUDED.max_sessions,
			session_limit_action = EXCLUDED.session_limit_action,
			mfa_enforcement = EXCLUDED.mfa_enforcement,
			mfa_grace_days = EXCLUDED.mfa_grace_days,
			step_up_window = EXCLUDED.step_up_window,
			step_up_methods = EXCLUDED.step_up_methods,
			mfa_enforced_since = CASE
				WHEN EXCLUDED.mfa_enforcement = 'optional' THEN NULL
				WHEN security_policies.mfa_enforcement = 'optional' THEN NOW()
				ELSE COALESCE(security_policies.mfa_enforced_since, NOW())
			END,
			settings = EXCLUDED.settings,
			updated_at = NOW()
		RETURNING mfa_enforced_since
	`, p.TenantID, p.PasswordMinLength,
		p.PasswordComplexity, int64(time.Duration(p.SessionMaxAge).Seconds()),
		int64(time.Duration(p.SessionIdleTimeout).Seconds()), p.MFAEnforcement, settings,
		p.MaxSessions, p.SessionLimitAction, p.MFAGraceDays,
		int64(stepUpWindow.Seconds()), p.StepUpMethods).Scan(&enforcedSince)
	return enforcedSince, err
}

// policyUpdate is the body of PUT /tenants/{id}/policy. Address rules are the
// only address control: empty ip_allowlist and ip_denylist are accepted, but
// entries are refused, so nobody believes a list protects them.
type policyUpdate struct {
	Policy
	IPAllowlist []string `json:"ip_allowlist"`
	IPDenylist  []string `json:"ip_denylist"`
}

func (u policyUpdate) retiredFields() []errs.FieldError {
	var bad []errs.FieldError
	for name, list := range map[string][]string{"ip_allowlist": u.IPAllowlist, "ip_denylist": u.IPDenylist} {
		if len(list) > 0 {
			bad = append(bad, errs.FieldError{Field: name, Code: "retired",
				Message: "The security policy no longer holds IP lists. Add address rules instead (Security → Address rules)."})
		}
	}
	return bad
}

// Handler serves the security policy HTTP API.
type Handler struct {
	Repo *Repository
}

// Mount registers the security policy routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/policy", h.get)
	r.Put("/tenants/{tenantID}/policy", h.put)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	p, err := h.Repo.Get(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	var body policyUpdate
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if bad := body.retiredFields(); len(bad) > 0 {
		httpx.WriteError(w, r, errs.ErrValidationFailed.WithFields(bad))
		return
	}
	in := body.Policy
	in.TenantID = tid
	if bad := h.Repo.normalize(&in); len(bad) > 0 {
		httpx.WriteError(w, r, errs.ErrValidationFailed.WithFields(bad))
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if in.MFAEnforcedSince, err = h.Repo.Upsert(ctx, tx, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	target := tid
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &target,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "security_policy.updated",
		ResourceType: "tenant",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata: map[string]any{
			"mfa_enforcement":      in.MFAEnforcement,
			"mfa_grace_days":       in.MFAGraceDays,
			"password_min_length":  in.PasswordMinLength,
			"session_max_age_s":    int64(time.Duration(in.SessionMaxAge).Seconds()),
			"session_idle_s":       int64(time.Duration(in.SessionIdleTimeout).Seconds()),
			"max_sessions":         in.MaxSessions,
			"session_limit_action": in.SessionLimitAction,
			"step_up_window_s":     int64(time.Duration(in.StepUpWindow).Seconds()),
			"step_up_methods":      in.StepUpMethods,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, in)
}
