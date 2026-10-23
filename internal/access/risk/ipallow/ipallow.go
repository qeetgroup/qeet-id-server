// Package ipallow manages per-tenant IP allow and deny rules (CIDRs). Deny
// rules win, and if any allow rule exists an address must match one. Rules are
// enforced only while the tenant's flag is on; then every sign-in to the
// organisation and every session renewal in it calls CheckSignIn.
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

// Rule is an organisation address rule: CIDR is allowed or denied according to
// Action ("allow" or "deny").
type Rule struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	CIDR      string    `json:"cidr"`
	Label     string    `json:"label"`
	Action    string    `json:"action"`
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

// Decision.Reason values: the exported ones are refusals, as recorded in
// auth.address_refused. reasonEnforcingOff is Check's reason when rules are off.
const (
	ReasonDenyRule     = "deny_rule"
	ReasonNotAllowed   = "not_in_allow_rules"
	ReasonUnknownAddr  = "address_unknown"
	reasonAllowed      = "allowed"
	reasonEnforcingOff = "enforcement disabled"
)

// Decide judges ipStr against rules. An address that can't be read is refused,
// so a sign-in from an unknown address can't get past enforced rules.
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

// CheckSignIn returns errs.ErrAuthAddressNotAllowed when the tenant's enforced
// rules refuse ip (from httpx.ClientIP), after recording auth.address_refused in
// its own transaction so the record outlives the sign-in. path names the
// sign-in. With rules off or no tenant it allows all; read errors are returned.
func (s *Service) CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	d, err := decideSignIn(ctx, s.q, tenantID, ip)
	if err != nil || d.Allowed {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, refusalEvent(tenantID, userID, ip, path, d)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return errs.ErrAuthAddressNotAllowed
}

// CheckSignInTx is CheckSignIn inside the caller's transaction: the rules are
// read, and a refusal recorded, through tx, which the caller commits to keep
// the record.
func (s *Service) CheckSignInTx(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, ip, path string) error {
	d, err := decideSignIn(ctx, s.q.WithTx(tx), tenantID, ip)
	if err != nil || d.Allowed {
		return err
	}
	if err := audit.Record(ctx, tx, refusalEvent(tenantID, userID, ip, path, d)); err != nil {
		return err
	}
	return errs.ErrAuthAddressNotAllowed
}

// decideSignIn judges ip against tenantID's rules, read through q. With no
// tenant, or rules not enforced, it is allowed.
func decideSignIn(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, ip string) (Decision, error) {
	allowed := Decision{Allowed: true, Reason: reasonAllowed}
	if tenantID == uuid.Nil {
		return allowed, nil
	}
	enabled, err := q.GetIPRulesEnabled(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return allowed, nil
	}
	if err != nil {
		return Decision{}, err
	}
	if !enabled {
		return allowed, nil
	}
	rows, err := q.ListIPRules(ctx, tenantID)
	if err != nil {
		return Decision{}, err
	}
	rules := make([]Rule, len(rows))
	for i, r := range rows {
		rules[i] = ruleFromModel(r)
	}
	return Decide(rules, ip), nil
}

// refusalEvent is the auth.address_refused record of a sign-in that d refuses.
func refusalEvent(tenantID, userID uuid.UUID, ip, path string, d Decision) audit.Event {
	meta := map[string]any{"reason": d.Reason, "path": path, "address": ip}
	var ruleID *uuid.UUID
	if d.Rule != nil {
		id := d.Rule.ID
		ruleID = &id
		meta["rule_id"] = id
		meta["cidr"] = d.Rule.CIDR
	}
	var actor *uuid.UUID
	if userID != uuid.Nil {
		actor = &userID
	}
	// The address column takes only a readable address; an unreadable one is
	// kept in the metadata alone.
	recordedIP := ip
	if d.Reason == ReasonUnknownAddr {
		recordedIP = ""
	}
	return audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actor,
		ActorType:    "user",
		Action:       "auth.address_refused",
		ResourceType: "ip_rule",
		ResourceID:   ruleID,
		IP:           recordedIP,
		Metadata:     meta,
	}
}

// refusesCaller returns ErrRiskRulesLockOutCaller if rules would refuse the
// caller's own address, so an organisation can't lock its admins out. For the
// console, that is the console server's address.
func refusesCaller(rules []Rule, r *http.Request) error {
	if d := Decide(rules, httpx.ClientIP(r)); !d.Allowed {
		return errs.ErrRiskRulesLockOutCaller.WithDetail("your address as the API sees it: " + httpx.ClientIP(r))
	}
	return nil
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

// guardEnforced refuses a rule change, inside its transaction, when the rules
// are enforced and the rule set it leaves would refuse the caller.
func (h *Handler) guardEnforced(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID uuid.UUID) error {
	q := h.Service.q.WithTx(tx)
	enabled, err := q.GetIPRulesEnabled(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := q.ListIPRules(ctx, tenantID)
	if err != nil {
		return err
	}
	rules := make([]Rule, len(rows))
	for i, row := range rows {
		rules[i] = ruleFromModel(row)
	}
	return refusesCaller(rules, r)
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
	if in.Enabled {
		rules, err := h.Service.ListRules(ctx, tenantID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := refusesCaller(rules, r); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
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
	if err := h.guardEnforced(ctx, tx, r, tenantID); err != nil {
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
	if err := h.guardEnforced(ctx, tx, r, tenantID); err != nil {
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
