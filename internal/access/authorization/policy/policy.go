// Package policy stores per-tenant security policy and offers an IP
// allow/deny middleware.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

type Policy struct {
	TenantID           uuid.UUID `json:"tenant_id"`
	IPAllowlist        []string  `json:"ip_allowlist"`
	IPDenylist         []string  `json:"ip_denylist"`
	PasswordMinLength  int       `json:"password_min_length"`
	PasswordComplexity string    `json:"password_complexity"`
	// SessionMaxAge ends a session that long after sign-in however active it
	// is, and bounds an application's grant; SessionIdleTimeout ends a
	// session that goes that long without being renewed. Both apply to
	// sessions opened after they are set. Zero on update = the platform
	// default.
	SessionMaxAge      Duration `json:"session_max_age"`
	SessionIdleTimeout Duration `json:"session_idle_timeout"`
	// MaxSessions caps how many live sessions one person may hold in the
	// organisation at once (nil: no limit). SessionLimitAction is what a
	// sign-in at the cap does: "evict_oldest" ends their least recently used
	// session, "refuse" refuses the sign-in. An ended session's renewal stops
	// at once; an access token it already issued lasts out its own short
	// lifetime (ACCESS_TOKEN_TTL).
	MaxSessions        *int           `json:"max_sessions"`
	SessionLimitAction string         `json:"session_limit_action"`
	MFAEnforcement     string         `json:"mfa_enforcement"`
	Settings           map[string]any `json:"settings"`
}

// Duration is a time.Duration written to JSON as a duration string ("720h",
// "30m"), the form the console edits. It reads that form, or a number of
// nanoseconds (how earlier responses wrote it).
type Duration time.Duration

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

// The values password_complexity and mfa_enforcement may take (the table's
// CHECK constraints).
var (
	passwordComplexities = map[string]bool{"relaxed": true, "standard": true, "strict": true}
	sessionLimitActions  = map[string]bool{"evict_oldest": true, "refuse": true}
	mfaEnforcements      = map[string]bool{"optional": true, "required": true, "admin_only": true}
)

type Repository struct {
	pool *pgxpool.Pool
	// The session bounds of an organisation that has not set its own
	// (config SESSION_MAX_AGE, SESSION_IDLE_TIMEOUT). Set by SetSessionDefaults.
	sessionMaxAge time.Duration
	sessionIdle   time.Duration
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, sessionMaxAge: 30 * 24 * time.Hour, sessionIdle: 24 * time.Hour}
}

// SetSessionDefaults sets the session bounds reported for an organisation
// that has not set its own, and stored for one that saves its policy without
// them. Called from internal/bootstrap/dependencies.go.
func (r *Repository) SetSessionDefaults(maxAge, idle time.Duration) {
	r.sessionMaxAge, r.sessionIdle = maxAge, idle
}

// normalize fills what an update left out — no IP lists, session bounds left
// zero (the platform defaults, the idle timeout no longer than the maximum
// age) — and reports the fields that are out of range.
func (r *Repository) normalize(p *Policy) []errs.FieldError {
	if p.IPAllowlist == nil {
		p.IPAllowlist = []string{}
	}
	if p.IPDenylist == nil {
		p.IPDenylist = []string{}
	}
	if p.SessionLimitAction == "" {
		p.SessionLimitAction = "evict_oldest"
	}
	if p.SessionMaxAge == 0 {
		p.SessionMaxAge = Duration(r.sessionMaxAge)
	}
	if p.SessionIdleTimeout == 0 {
		p.SessionIdleTimeout = Duration(min(r.sessionIdle, time.Duration(p.SessionMaxAge)))
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
	if p.MaxSessions != nil && (*p.MaxSessions < 1 || *p.MaxSessions > 1000) {
		field("max_sessions", "Set the session limit between 1 and 1000, or leave it empty for no limit.")
	}
	if !sessionLimitActions[p.SessionLimitAction] {
		field("session_limit_action", "Choose evict_oldest or refuse.")
	}
	return bad
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	var p Policy
	var allow, deny []string
	var settings []byte
	var sessionAge, sessionIdle int64
	err := r.pool.QueryRow(ctx, `
		SELECT tenant_id, ip_allowlist::text[], ip_denylist::text[],
		       password_min_length, password_complexity,
		       EXTRACT(EPOCH FROM session_max_age)::bigint,
		       EXTRACT(EPOCH FROM session_idle_timeout)::bigint,
		       max_sessions, session_limit_action,
		       mfa_enforcement, settings
		FROM tenant.security_policies WHERE tenant_id = $1
	`, tenantID).Scan(&p.TenantID, &allow, &deny, &p.PasswordMinLength,
		&p.PasswordComplexity, &sessionAge, &sessionIdle, &p.MaxSessions, &p.SessionLimitAction, &p.MFAEnforcement, &settings)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Policy{
			TenantID:           tenantID,
			IPAllowlist:        []string{},
			IPDenylist:         []string{},
			PasswordMinLength:  8,
			PasswordComplexity: "standard",
			SessionMaxAge:      Duration(r.sessionMaxAge),
			SessionIdleTimeout: Duration(r.sessionIdle),
			SessionLimitAction: "evict_oldest",
			MFAEnforcement:     "optional",
			Settings:           map[string]any{},
		}, nil
	}
	if err != nil {
		return nil, err
	}
	p.IPAllowlist = allow
	p.IPDenylist = deny
	p.SessionMaxAge = Duration(time.Duration(sessionAge) * time.Second)
	p.SessionIdleTimeout = Duration(time.Duration(sessionIdle) * time.Second)
	p.Settings = dbutil.Metadata(settings)
	return &p, nil
}

func (r *Repository) Upsert(ctx context.Context, tx pgx.Tx, p Policy) error {
	settings, _ := json.Marshal(p.Settings)
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant.security_policies (
			tenant_id, ip_allowlist, ip_denylist,
			password_min_length, password_complexity,
			session_max_age, session_idle_timeout, mfa_enforcement, settings,
			max_sessions, session_limit_action
		) VALUES ($1, $2::cidr[], $3::cidr[], $4, $5, make_interval(secs => $6::bigint),
		         make_interval(secs => $7::bigint), $8,
		         COALESCE(NULLIF($9::jsonb,'null'::jsonb), '{}'::jsonb), $10, COALESCE(NULLIF($11, ''), 'evict_oldest'))
		ON CONFLICT (tenant_id) DO UPDATE SET
			ip_allowlist = EXCLUDED.ip_allowlist,
			ip_denylist = EXCLUDED.ip_denylist,
			password_min_length = EXCLUDED.password_min_length,
			password_complexity = EXCLUDED.password_complexity,
			session_max_age = EXCLUDED.session_max_age,
			session_idle_timeout = EXCLUDED.session_idle_timeout,
			max_sessions = EXCLUDED.max_sessions,
			session_limit_action = EXCLUDED.session_limit_action,
			mfa_enforcement = EXCLUDED.mfa_enforcement,
			settings = EXCLUDED.settings,
			updated_at = NOW()
	`, p.TenantID, p.IPAllowlist, p.IPDenylist, p.PasswordMinLength,
		p.PasswordComplexity, int64(time.Duration(p.SessionMaxAge).Seconds()),
		int64(time.Duration(p.SessionIdleTimeout).Seconds()), p.MFAEnforcement, settings,
		p.MaxSessions, p.SessionLimitAction)
	return err
}

// Allowed returns true if the IP is permitted by the policy. Empty
// allowlist means "everything except denylist".
func (p *Policy) Allowed(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, cidr := range p.IPDenylist {
		if cidrContains(cidr, ip) {
			return false
		}
	}
	if len(p.IPAllowlist) == 0 {
		return true
	}
	for _, cidr := range p.IPAllowlist {
		if cidrContains(cidr, ip) {
			return true
		}
	}
	return false
}

func cidrContains(cidr string, ip net.IP) bool {
	if cidr == "" {
		return false
	}
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		return ipnet.Contains(ip)
	}
	return cidr == ip.String()
}

type Handler struct {
	Repo *Repository
}

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

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	var in Policy
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
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
	if err := h.Repo.Upsert(ctx, tx, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
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
			"ip_allowlist_count":   len(in.IPAllowlist),
			"ip_denylist_count":    len(in.IPDenylist),
			"mfa_enforcement":      in.MFAEnforcement,
			"password_min_length":  in.PasswordMinLength,
			"session_max_age_s":    int64(time.Duration(in.SessionMaxAge).Seconds()),
			"session_idle_s":       int64(time.Duration(in.SessionIdleTimeout).Seconds()),
			"max_sessions":         in.MaxSessions,
			"session_limit_action": in.SessionLimitAction,
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
