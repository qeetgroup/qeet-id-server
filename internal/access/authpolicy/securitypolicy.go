package authpolicy

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SecurityPolicy is an organization's sessions, second-factor and step-up policy. Session and step-up
// settings left zero on update take the defaults; session settings apply to sessions opened after
// they're set. Which addresses may sign in is the address rules' (internal/access/ipallow).
type SecurityPolicy struct {
	OrganizationID uuid.UUID `json:"organization_id"`

	// Deprecated: accepted and ignored, and never returned. Password rules are
	// the auth policy's (PUT /v1/organizations/{organizationID}/auth-policy).
	PasswordMinLength  int    `json:"password_min_length,omitempty"`
	PasswordComplexity string `json:"password_complexity,omitempty"`

	// A session ends SessionMaxAge after sign-in however active, which also
	// bounds an application's grant, or after SessionIdleTimeout unrenewed.
	SessionMaxAge      Duration `json:"session_max_age"`
	SessionIdleTimeout Duration `json:"session_idle_timeout"`

	// MaxSessions caps one person's live sessions here (nil: no limit). At the
	// cap a sign-in ends their least recently used one ("evict_oldest"; its
	// access tokens are refused from then on) or is refused ("refuse").
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
	sessionLimitActions = map[string]bool{"evict_oldest": true, "refuse": true}
	mfaEnforcements     = map[string]bool{"optional": true, "required": true, "admin_only": true}
	stepUpMethods       = map[string]bool{"totp": true, "recovery_code": true, "otp": true, "webauthn": true, "push": true}
)

// The bounds of a step-up window, and the window of an organization that sets
// none (the column default).
const (
	stepUpWindowMin     = time.Minute
	stepUpWindowMax     = time.Hour
	stepUpWindowDefault = 5 * time.Minute
)

// SecurityPolicies stores security policies. sessionMaxAge and sessionIdle are
// the session bounds of an organization that sets none (SESSION_MAX_AGE and
// SESSION_IDLE_TIMEOUT).
type SecurityPolicies struct {
	pool          *pgxpool.Pool
	q             *dbgen.Queries
	sessionMaxAge time.Duration
	sessionIdle   time.Duration
}

// NewSecurityPolicies returns a SecurityPolicies over pool. maxAge and idle
// are the session bounds reported for an organization that has not set its
// own, and stored for one that saves its policy without them; zero is 30 days
// and 24 hours.
func NewSecurityPolicies(pool *pgxpool.Pool, maxAge, idle time.Duration) *SecurityPolicies {
	return &SecurityPolicies{pool: pool, q: dbgen.New(pool),
		sessionMaxAge: cmp.Or(maxAge, 30*24*time.Hour), sessionIdle: cmp.Or(idle, 24*time.Hour)}
}

// normalize fills what an update left zero (the platform session bounds, with
// the idle timeout capped at the maximum age, and the default step-up window)
// and reports the fields that are out of range.
func (r *SecurityPolicies) normalize(p *SecurityPolicy) []errs.FieldError {
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

// Get returns the organization's security policy, or the defaults when it has none.
func (r *SecurityPolicies) Get(ctx context.Context, organizationID uuid.UUID) (*SecurityPolicy, error) {
	return r.get(ctx, r.q, organizationID)
}

// Replace stores p as the organization's security policy, recorded as actor's,
// and returns it as stored.
func (r *SecurityPolicies) Replace(ctx context.Context, organizationID uuid.UUID, p SecurityPolicy, actor audit.Actor) (*SecurityPolicy, error) {
	return r.change(ctx, organizationID, actor, func(*dbgen.Queries) (SecurityPolicy, error) { return p, nil })
}

// Patch stores the policy edit makes of the stored one, recorded as actor's,
// and returns it as stored. The policy stays locked from the read to the
// write, so a change saved meanwhile is not lost.
func (r *SecurityPolicies) Patch(ctx context.Context, organizationID uuid.UUID, edit func(*SecurityPolicy) error, actor audit.Actor) (*SecurityPolicy, error) {
	return r.change(ctx, organizationID, actor, func(q *dbgen.Queries) (SecurityPolicy, error) {
		current, err := r.get(ctx, q, organizationID)
		if err != nil {
			return SecurityPolicy{}, err
		}
		if err := edit(current); err != nil {
			return SecurityPolicy{}, err
		}
		return *current, nil
	})
}

// change stores, under the organization's policy lock, the policy next
// returns once it validates, and audits it in the same transaction.
func (r *SecurityPolicies) change(ctx context.Context, organizationID uuid.UUID, actor audit.Actor, next func(*dbgen.Queries) (SecurityPolicy, error)) (*SecurityPolicy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := lockForChange(ctx, tx, organizationID); err != nil {
		return nil, err
	}
	q := r.q.WithTx(tx)
	in, err := next(q)
	if err != nil {
		return nil, err
	}
	in.OrganizationID = organizationID
	if bad := r.normalize(&in); len(bad) > 0 {
		return nil, errs.ErrValidationFailed.WithFields(bad)
	}
	if in.MFAEnforcedSince, err = upsert(ctx, q, in); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "security_policy.updated", "organization", organizationID, map[string]any{
		"mfa_enforcement":      in.MFAEnforcement,
		"mfa_grace_days":       in.MFAGraceDays,
		"session_max_age_s":    int64(time.Duration(in.SessionMaxAge).Seconds()),
		"session_idle_s":       int64(time.Duration(in.SessionIdleTimeout).Seconds()),
		"max_sessions":         in.MaxSessions,
		"session_limit_action": in.SessionLimitAction,
		"step_up_window_s":     int64(time.Duration(in.StepUpWindow).Seconds()),
		"step_up_methods":      in.StepUpMethods,
	})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &in, nil
}

// lockForChange takes, on tx, the organization's policy lock, so a change based on
// the stored policy can't lose one made meanwhile.
func lockForChange(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID) error {
	// Raw SQL: pg_advisory_xact_lock returns void, which sqlc cannot model.
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security_policy:' || $1::text, 0))`, organizationID)
	return err
}

func (r *SecurityPolicies) get(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID) (*SecurityPolicy, error) {
	row, err := q.GetSecurityPolicy(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &SecurityPolicy{
			OrganizationID:     organizationID,
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
	p := SecurityPolicy{
		OrganizationID:     row.OrganizationID,
		SessionMaxAge:      Duration(time.Duration(row.SessionMaxAgeS) * time.Second),
		SessionIdleTimeout: Duration(time.Duration(row.SessionIdleS) * time.Second),
		SessionLimitAction: row.SessionLimitAction,
		MFAEnforcement:     row.MfaEnforcement,
		MFAGraceDays:       int(row.MfaGraceDays),
		MFAEnforcedSince:   row.MfaEnforcedSince,
		StepUpWindow:       Duration(time.Duration(row.StepUpWindowS) * time.Second),
		StepUpMethods:      row.StepUpMethods,
		Settings:           postgres.Metadata(row.Settings),
	}
	if row.MaxSessions != nil {
		p.MaxSessions = new(int(*row.MaxSessions))
	}
	return &p, nil
}

// upsert stores the policy and returns when its MFA requirement was turned on
// (nil while optional): the moment it changes from optional, kept while it
// stays on — moving between required and admin_only does not restart a grace
// period.
func upsert(ctx context.Context, q *dbgen.Queries, p SecurityPolicy) (*time.Time, error) {
	settings, _ := json.Marshal(p.Settings)
	stepUpWindow := time.Duration(p.StepUpWindow)
	if stepUpWindow == 0 {
		stepUpWindow = stepUpWindowDefault
	}
	params := dbgen.UpsertSecurityPolicyParams{
		OrganizationID:     p.OrganizationID,
		SessionMaxAgeS:     int64(time.Duration(p.SessionMaxAge).Seconds()),
		SessionIdleS:       int64(time.Duration(p.SessionIdleTimeout).Seconds()),
		MfaEnforcement:     p.MFAEnforcement,
		Settings:           settings,
		SessionLimitAction: p.SessionLimitAction,
		MfaGraceDays:       int32(p.MFAGraceDays), // #nosec G115 -- normalize keeps it within 0..90
		StepUpWindowS:      int64(stepUpWindow.Seconds()),
		StepUpMethods:      p.StepUpMethods,
	}
	if p.MaxSessions != nil {
		params.MaxSessions = new(int32(*p.MaxSessions)) // #nosec G115 -- normalize keeps it within 1..1000
	}
	return q.UpsertSecurityPolicy(ctx, params)
}
