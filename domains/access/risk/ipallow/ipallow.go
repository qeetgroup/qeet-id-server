// Package ipallow manages per-tenant IP allow/deny rules (CIDR) and evaluates
// an address against them. Deny rules win; if any allow rule exists, an address
// must match one to pass. Enforcement in the request path is gated by an
// explicit per-tenant flag (avoids accidental lockout) and is exposed here as a
// pure Evaluate + a /check endpoint; wiring it as edge/middleware enforcement
// (with caching) is a deployment step.
package ipallow

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

type Rule struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	CIDR      string    `json:"cidr"`
	Label     string    `json:"label"`
	Action    string    `json:"action"` // allow | deny
	CreatedAt time.Time `json:"created_at"`
}

// parsePrefix accepts a CIDR ("10.0.0.0/8") or a bare address ("1.2.3.4",
// treated as a host route /32 or /128).
func parsePrefix(cidr string) (netip.Prefix, error) {
	cidr = strings.TrimSpace(cidr)
	if strings.Contains(cidr, "/") {
		return netip.ParsePrefix(cidr)
	}
	addr, err := netip.ParseAddr(cidr)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

// Evaluate decides whether ipStr is permitted by the rule set. Pure, so it is
// unit-tested without a database. An unparseable address fails open.
func Evaluate(rules []Rule, ipStr string) (bool, string) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return true, "allowed (unparseable address — not enforced)"
	}
	hasAllow, inAllow := false, false
	for _, r := range rules {
		pfx, perr := parsePrefix(r.CIDR)
		if perr != nil {
			continue
		}
		match := pfx.Contains(ip)
		if r.Action == "deny" && match {
			return false, "blocked by deny rule " + r.CIDR
		}
		if r.Action == "allow" {
			hasAllow = true
			if match {
				inAllow = true
			}
		}
	}
	if hasAllow && !inAllow {
		return false, "not in any allow rule"
	}
	return true, "allowed"
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) ListRules(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, cidr, label, action, created_at
		FROM tenant.ip_rules WHERE tenant_id = $1 ORDER BY action, created_at
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.TenantID, &r.CIDR, &r.Label, &r.Action, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) Enabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var enabled bool
	err := s.pool.QueryRow(ctx, `SELECT enabled FROM tenant.ip_rules_config WHERE tenant_id = $1`, tenantID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return enabled, err
}

func (s *Service) SetEnabled(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, enabled bool) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant.ip_rules_config (tenant_id, enabled, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()
	`, tenantID, enabled)
	return err
}

func (s *Service) AddRule(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, cidr, label, action string) (*Rule, error) {
	if _, err := parsePrefix(cidr); err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("invalid CIDR or IP address")
	}
	if action != "allow" && action != "deny" {
		action = "allow"
	}
	var r Rule
	err := tx.QueryRow(ctx, `
		INSERT INTO tenant.ip_rules (tenant_id, cidr, label, action)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, cidr, label, action, created_at
	`, tenantID, strings.TrimSpace(cidr), label, action).Scan(&r.ID, &r.TenantID, &r.CIDR, &r.Label, &r.Action, &r.CreatedAt)
	return &r, err
}

func (s *Service) DeleteRule(ctx context.Context, tx pgx.Tx, tenantID, ruleID uuid.UUID) error {
	ct, err := tx.Exec(ctx, `DELETE FROM tenant.ip_rules WHERE id = $1 AND tenant_id = $2`, ruleID, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Check evaluates an address against the tenant's rules, honouring the enabled
// flag (disabled → always allowed).
func (s *Service) Check(ctx context.Context, tenantID uuid.UUID, ip string) (enabled, allowed bool, reason string, err error) {
	enabled, err = s.Enabled(ctx, tenantID)
	if err != nil {
		return false, true, "", err
	}
	if !enabled {
		return false, true, "enforcement disabled", nil
	}
	rules, err := s.ListRules(ctx, tenantID)
	if err != nil {
		return enabled, true, "", err
	}
	allowed, reason = Evaluate(rules, ip)
	return enabled, allowed, reason, nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/ip-rules", h.list)
	r.Put("/tenants/{tenantID}/ip-rules/config", h.setConfig)
	r.Post("/tenants/{tenantID}/ip-rules", h.add)
	r.Delete("/tenants/{tenantID}/ip-rules/{ruleID}", h.del)
	r.Post("/tenants/{tenantID}/ip-rules/check", h.check)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID uuid.UUID, action string, meta map[string]any) error {
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := tenantID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "ip_rule",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	enabled, err := h.Service.Enabled(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rules, err := h.Service.ListRules(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "items": rules})
}

func (h *Handler) setConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.SetEnabled(ctx, tx, tenantID, in.Enabled); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, "ip_rules.enforcement_changed", map[string]any{"enabled": in.Enabled}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": in.Enabled})
}

func (h *Handler) add(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		CIDR   string `json:"cidr"`
		Label  string `json:"label"`
		Action string `json:"action"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	rule, err := h.Service.AddRule(ctx, tx, tenantID, in.CIDR, in.Label, in.Action)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, "ip_rules.rule_added", map[string]any{"cidr": rule.CIDR, "action": rule.Action}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, rule)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid ruleID"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.DeleteRule(ctx, tx, tenantID, ruleID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, "ip_rules.rule_removed", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	enabled, allowed, reason, err := h.Service.Check(r.Context(), tenantID, in.IP)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "allowed": allowed, "reason": reason})
}
