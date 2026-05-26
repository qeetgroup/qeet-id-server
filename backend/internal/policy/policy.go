// Package policy stores per-tenant security policy and offers an IP
// allow/deny middleware.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Policy struct {
	TenantID          uuid.UUID      `json:"tenant_id"`
	IPAllowlist       []string       `json:"ip_allowlist"`
	IPDenylist        []string       `json:"ip_denylist"`
	PasswordMinLength int            `json:"password_min_length"`
	PasswordComplexity string        `json:"password_complexity"`
	SessionMaxAge     time.Duration  `json:"session_max_age"`
	MFAEnforcement    string         `json:"mfa_enforcement"`
	Settings          map[string]any `json:"settings"`
}

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	var p Policy
	var allow, deny []string
	var settings []byte
	var sessionAge time.Duration
	err := r.pool.QueryRow(ctx, `
		SELECT tenant_id, ip_allowlist::text[], ip_denylist::text[],
		       password_min_length, password_complexity,
		       EXTRACT(EPOCH FROM session_max_age) * INTERVAL '1 second',
		       mfa_enforcement, settings
		FROM tenant.security_policies WHERE tenant_id = $1
	`, tenantID).Scan(&p.TenantID, &allow, &deny, &p.PasswordMinLength,
		&p.PasswordComplexity, &sessionAge, &p.MFAEnforcement, &settings)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Policy{
			TenantID:           tenantID,
			IPAllowlist:        []string{},
			IPDenylist:         []string{},
			PasswordMinLength:  8,
			PasswordComplexity: "standard",
			SessionMaxAge:      30 * 24 * time.Hour,
			MFAEnforcement:     "optional",
			Settings:           map[string]any{},
		}, nil
	}
	if err != nil {
		return nil, err
	}
	p.IPAllowlist = allow
	p.IPDenylist = deny
	p.SessionMaxAge = sessionAge
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &p.Settings)
	}
	if p.Settings == nil {
		p.Settings = map[string]any{}
	}
	return &p, nil
}

func (r *Repository) Upsert(ctx context.Context, tx pgx.Tx, p Policy) error {
	settings, _ := json.Marshal(p.Settings)
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant.security_policies (
			tenant_id, ip_allowlist, ip_denylist,
			password_min_length, password_complexity,
			session_max_age, mfa_enforcement, settings
		) VALUES ($1, $2::cidr[], $3::cidr[], $4, $5, ($6::bigint || ' seconds')::interval, $7,
		         COALESCE(NULLIF($8::jsonb,'null'::jsonb), '{}'::jsonb))
		ON CONFLICT (tenant_id) DO UPDATE SET
			ip_allowlist = EXCLUDED.ip_allowlist,
			ip_denylist = EXCLUDED.ip_denylist,
			password_min_length = EXCLUDED.password_min_length,
			password_complexity = EXCLUDED.password_complexity,
			session_max_age = EXCLUDED.session_max_age,
			mfa_enforcement = EXCLUDED.mfa_enforcement,
			settings = EXCLUDED.settings,
			updated_at = NOW()
	`, p.TenantID, p.IPAllowlist, p.IPDenylist, p.PasswordMinLength,
		p.PasswordComplexity, int64(p.SessionMaxAge.Seconds()), p.MFAEnforcement, settings)
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
			"ip_allowlist_count":  len(in.IPAllowlist),
			"ip_denylist_count":   len(in.IPDenylist),
			"mfa_enforcement":     in.MFAEnforcement,
			"password_min_length": in.PasswordMinLength,
			"session_max_age_s":   int64(in.SessionMaxAge.Seconds()),
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
