// Package ipallow manages per-tenant IP allow/deny rules (CIDR) and evaluates
// an address against them. Deny rules win; if any allow rule exists, an address
// must match one to pass. Enforcement is gated by an explicit per-tenant flag
// (avoids accidental lockout). While it is on, every sign-in to the
// organisation and every renewal of a session in it asks CheckSignIn first; the
// /check endpoint answers the same question for an admin.
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

	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// Decision is what the rules make of one address. Rule is the deny rule that
// matched, nil when no single rule is responsible (allowed, outside every
// allow rule, or no address to judge).
type Decision struct {
	Allowed bool
	Rule    *Rule
	Reason  string
}

// Why a decision refused an address, as recorded in auth.address_refused.
const (
	ReasonDenyRule     = "deny_rule"
	ReasonNotAllowed   = "not_in_allow_rules"
	ReasonUnknownAddr  = "address_unknown"
	reasonAllowed      = "allowed"
	reasonEnforcingOff = "enforcement disabled"
)

// Decide judges ipStr against the rule set. Pure, so it is unit-tested without
// a database. An address that can't be read is refused: while rules are on, a
// sign-in from an unknown address must not get past them.
func Decide(rules []Rule, ipStr string) Decision {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return Decision{Reason: ReasonUnknownAddr}
	}
	hasAllow, inAllow := false, false
	for i, r := range rules {
		pfx, perr := parsePrefix(r.CIDR)
		if perr != nil {
			continue
		}
		match := pfx.Contains(ip.Unmap())
		if r.Action == "deny" && match {
			return Decision{Rule: &rules[i], Reason: ReasonDenyRule}
		}
		if r.Action == "allow" {
			hasAllow = true
			if match {
				inAllow = true
			}
		}
	}
	if hasAllow && !inAllow {
		return Decision{Reason: ReasonNotAllowed}
	}
	return Decision{Allowed: true, Reason: reasonAllowed}
}

// Evaluate is Decide as (allowed, a sentence for an admin).
func Evaluate(rules []Rule, ipStr string) (bool, string) {
	d := Decide(rules, ipStr)
	switch d.Reason {
	case ReasonDenyRule:
		return false, "blocked by deny rule " + d.Rule.CIDR
	case ReasonNotAllowed:
		return false, "not in any allow rule"
	case ReasonUnknownAddr:
		return false, "refused: not a readable address"
	}
	return true, "allowed"
}

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// ruleFromModel converts the generated TenantIpRule to the domain Rule type.
func ruleFromModel(m dbgen.TenantIpRule) Rule {
	return Rule{
		ID:        m.ID,
		TenantID:  m.TenantID,
		CIDR:      m.Cidr,
		Label:     m.Label,
		Action:    m.Action,
		CreatedAt: m.CreatedAt,
	}
}

func (s *Service) ListRules(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	rows, err := s.q.ListIPRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, len(rows))
	for i, r := range rows {
		out[i] = ruleFromModel(r)
	}
	return out, nil
}

func (s *Service) Enabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	enabled, err := s.q.GetIPRulesEnabled(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return enabled, err
}

func (s *Service) SetEnabled(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, enabled bool) error {
	return s.q.WithTx(tx).SetIPRulesEnabled(ctx, dbgen.SetIPRulesEnabledParams{
		TenantID: tenantID,
		Enabled:  enabled,
	})
}

func (s *Service) AddRule(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, cidr, label, action string) (*Rule, error) {
	if _, err := parsePrefix(cidr); err != nil {
		return nil, errs.ErrRiskCIDRInvalid
	}
	if action != "allow" && action != "deny" {
		action = "allow"
	}
	m, err := s.q.WithTx(tx).InsertIPRule(ctx, dbgen.InsertIPRuleParams{
		TenantID: tenantID,
		Cidr:     strings.TrimSpace(cidr),
		Label:    label,
		Action:   action,
	})
	if err != nil {
		return nil, err
	}
	r := ruleFromModel(m)
	return &r, nil
}

func (s *Service) DeleteRule(ctx context.Context, tx pgx.Tx, tenantID, ruleID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteIPRule(ctx, dbgen.DeleteIPRuleParams{
		ID:       ruleID,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
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
		return false, true, reasonEnforcingOff, nil
	}
	rules, err := s.ListRules(ctx, tenantID)
	if err != nil {
		return enabled, true, "", err
	}
	allowed, reason = Evaluate(rules, ip)
	return enabled, allowed, reason, nil
}

// CheckSignIn is the gate every sign-in to an organisation, and every renewal
// of a session in it, passes before a session is issued or renewed. With the
// organisation's rules off (or no organisation) it allows everything. Refused,
// it records auth.address_refused — the rule responsible, the address and the
// path — in its own transaction, so the record survives the refused sign-in,
// and returns errs.ErrAuthAddressNotAllowed. ip is the address the platform
// derived for the request (httpx.ClientIP), never one the caller declared;
// path names the sign-in ("password", "passkey", "refresh", "oidc_authorize",
// …). A failure to read the rules is returned, so the sign-in fails closed.
func (s *Service) CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	if tenantID == uuid.Nil {
		return nil
	}
	enabled, err := s.Enabled(ctx, tenantID)
	if err != nil || !enabled {
		return err
	}
	rules, err := s.ListRules(ctx, tenantID)
	if err != nil {
		return err
	}
	d := Decide(rules, ip)
	if d.Allowed {
		return nil
	}
	meta := map[string]any{"reason": d.Reason, "path": path, "address": ip}
	var ruleID *uuid.UUID
	if d.Rule != nil {
		id := d.Rule.ID
		ruleID = &id
		meta["rule_id"] = id
		meta["cidr"] = d.Rule.CIDR
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tid := tenantID
	var actor *uuid.UUID
	if userID != uuid.Nil {
		uid := userID
		actor = &uid
	}
	// The address column takes only a readable address; an unreadable one is
	// kept in the metadata alone.
	recordedIP := ip
	if d.Reason == ReasonUnknownAddr {
		recordedIP = ""
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actor,
		ActorType:    "user",
		Action:       "auth.address_refused",
		ResourceType: "ip_rule",
		ResourceID:   ruleID,
		IP:           recordedIP,
		Metadata:     meta,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return errs.ErrAuthAddressNotAllowed
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
