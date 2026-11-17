// Package ipallow manages per-organization IP allow and deny rules (CIDRs). Deny
// rules win, and if any allow rule exists an address must match one. Rules are
// enforced only while the organization's flag is on; then every sign-in to the
// organization and every session renewal in it calls CheckSignIn.
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
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Rule is an organization address rule: CIDR is allowed or denied according to
// Action ("allow" or "deny").
type Rule struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"tenant_id"`
	CIDR           string    `json:"cidr"`
	Label          string    `json:"label"`
	Action         string    `json:"action"`
	CreatedAt      time.Time `json:"created_at"`
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
	return d.Allowed, d.sentence()
}

// sentence is d's reason in English, for an admin.
func (d Decision) sentence() string {
	switch d.Reason {
	case ReasonDenyRule:
		return "blocked by deny rule " + d.Rule.CIDR
	case ReasonNotAllowed:
		return "not in any allow rule"
	case ReasonUnknownAddr:
		return "refused: not a readable address"
	}
	return "allowed"
}

// CheckResult is what Check makes of an address. ReasonCode is "ip." and the
// Decision.Reason, or CodeEnforcementOff; Reason is the same in English.
// ReasonParams names the deny rule's CIDR when one refused it. Rules is what
// the rules decide whatever the enforcement flag, so they can be tried before
// they're turned on; with enforcement on it matches the rest.
type CheckResult struct {
	Enabled      bool           `json:"enabled"`
	Allowed      bool           `json:"allowed"`
	Reason       string         `json:"reason"`
	ReasonCode   string         `json:"reason_code"`
	ReasonParams map[string]any `json:"reason_params,omitempty"`
	Rules        RulesDecision  `json:"rules"`
}

// RulesDecision is what an organization's rules make of an address.
type RulesDecision struct {
	Allowed      bool           `json:"allowed"`
	Reason       string         `json:"reason"`
	ReasonCode   string         `json:"reason_code"`
	ReasonParams map[string]any `json:"reason_params,omitempty"`
}

// CodeEnforcementOff is Check's reason code when the rules are off.
const CodeEnforcementOff = "ip.enforcement_disabled"

// Service manages each organization's address rules and checks sign-ins against
// them.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the address rule service.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// ruleFromModel converts the generated OrganizationIpRule to the domain Rule type.
func ruleFromModel(m dbgen.OrganizationIpRule) Rule {
	return Rule{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		CIDR:           m.Cidr,
		Label:          m.Label,
		Action:         m.Action,
		CreatedAt:      m.CreatedAt,
	}
}

// ListRules returns the organization's address rules.
func (s *Service) ListRules(ctx context.Context, organizationID uuid.UUID) ([]Rule, error) {
	rows, err := s.q.ListIPRules(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, len(rows))
	for i, r := range rows {
		out[i] = ruleFromModel(r)
	}
	return out, nil
}

// Enabled reports whether the organization's address rules are on.
func (s *Service) Enabled(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	enabled, err := s.q.GetIPRulesEnabled(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return enabled, err
}

// SetEnabled turns the organization's address rules on or off.
func (s *Service) SetEnabled(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, enabled bool) error {
	return s.q.WithTx(tx).SetIPRulesEnabled(ctx, dbgen.SetIPRulesEnabledParams{
		OrganizationID: organizationID,
		Enabled:        enabled,
	})
}

// AddRule adds an allow or deny rule for a CIDR range to the organization. No action
// means allow; any other action is refused, so a mistyped deny never allows.
func (s *Service) AddRule(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, cidr, label, action string) (*Rule, error) {
	if _, err := parsePrefix(cidr); err != nil {
		return nil, errs.ErrRiskCIDRInvalid
	}
	switch action {
	case "":
		action = "allow"
	case "allow", "deny":
	default:
		return nil, errs.ErrRiskRuleActionInvalid
	}
	m, err := s.q.WithTx(tx).InsertIPRule(ctx, dbgen.InsertIPRuleParams{
		OrganizationID: organizationID,
		Cidr:           strings.TrimSpace(cidr),
		Label:          label,
		Action:         action,
	})
	if err != nil {
		return nil, err
	}
	r := ruleFromModel(m)
	return &r, nil
}

// DeleteRule removes one of the organization's address rules and returns it.
func (s *Service) DeleteRule(ctx context.Context, tx pgx.Tx, organizationID, ruleID uuid.UUID) (*Rule, error) {
	m, err := s.q.WithTx(tx).DeleteIPRule(ctx, dbgen.DeleteIPRuleParams{
		ID:             ruleID,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r := ruleFromModel(m)
	return &r, nil
}

// Check evaluates an address against the organization's rules, honouring the enabled
// flag (disabled → always allowed).
func (s *Service) Check(ctx context.Context, organizationID uuid.UUID, ip string) (CheckResult, error) {
	enabled, err := s.Enabled(ctx, organizationID)
	if err != nil {
		return CheckResult{}, err
	}
	rules, err := s.ListRules(ctx, organizationID)
	if err != nil {
		return CheckResult{}, err
	}
	d := Decide(rules, ip)
	decision := RulesDecision{Allowed: d.Allowed, Reason: d.sentence(), ReasonCode: "ip." + d.Reason}
	if d.Rule != nil {
		decision.ReasonParams = map[string]any{"cidr": d.Rule.CIDR}
	}
	if !enabled {
		return CheckResult{Allowed: true, Reason: reasonEnforcingOff, ReasonCode: CodeEnforcementOff, Rules: decision}, nil
	}
	return CheckResult{Enabled: true, Allowed: decision.Allowed, Reason: decision.Reason,
		ReasonCode: decision.ReasonCode, ReasonParams: decision.ReasonParams, Rules: decision}, nil
}

// CheckSignIn returns errs.ErrAuthAddressNotAllowed when the organization's enforced
// rules refuse ip (from httpx.ClientIP), after recording auth.address_refused in
// its own transaction so the record outlives the sign-in. path names the
// sign-in. With rules off or no organization it allows all; read errors are returned.
func (s *Service) CheckSignIn(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	d, err := decideSignIn(ctx, s.q, organizationID, ip)
	if err != nil || d.Allowed {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, refusalEvent(organizationID, userID, ip, path, d)); err != nil {
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
func (s *Service) CheckSignInTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error {
	d, err := decideSignIn(ctx, s.q.WithTx(tx), organizationID, ip)
	if err != nil || d.Allowed {
		return err
	}
	if err := audit.Record(ctx, tx, refusalEvent(organizationID, userID, ip, path, d)); err != nil {
		return err
	}
	return errs.ErrAuthAddressNotAllowed
}

// decideSignIn judges ip against organizationID's rules, read through q. With no
// organization, or rules not enforced, it is allowed.
func decideSignIn(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, ip string) (Decision, error) {
	allowed := Decision{Allowed: true, Reason: reasonAllowed}
	if organizationID == uuid.Nil {
		return allowed, nil
	}
	enabled, err := q.GetIPRulesEnabled(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return allowed, nil
	}
	if err != nil {
		return Decision{}, err
	}
	if !enabled {
		return allowed, nil
	}
	rows, err := q.ListIPRules(ctx, organizationID)
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
func refusalEvent(organizationID, userID uuid.UUID, ip, path string, d Decision) audit.Event {
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
		OrganizationID: &organizationID,
		ActorUserID:    actor,
		ActorType:      "user",
		Action:         "auth.address_refused",
		ResourceType:   "ip_rule",
		ResourceID:     ruleID,
		IP:             recordedIP,
		Metadata:       meta,
	}
}

// refusesCaller returns ErrRiskRulesLockOutCaller if rules would refuse the
// caller's own address, so an organization can't lock its admins out. For the
// console, that is the console server's address.
func refusesCaller(rules []Rule, r *http.Request) error {
	if d := Decide(rules, httpx.ClientIP(r)); !d.Allowed {
		return errs.ErrRiskRulesLockOutCaller.WithDetail("your address as the API sees it: " + httpx.ClientIP(r))
	}
	return nil
}

// Handler serves the address rule HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the address rule routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/ip-rules", h.list)
	r.Put("/tenants/{tenantID}/ip-rules/config", h.setConfig)
	r.Post("/tenants/{tenantID}/ip-rules", h.add)
	r.Delete("/tenants/{tenantID}/ip-rules/{ruleID}", h.del)
	r.Post("/tenants/{tenantID}/ip-rules/check", h.check)
}

// ruleMetadata is what an audit event says of the rule it changed.
func ruleMetadata(rule *Rule) map[string]any {
	return map[string]any{"cidr": rule.CIDR, "action": rule.Action, "label": rule.Label}
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID uuid.UUID, ruleID *uuid.UUID, action string, meta map[string]any) error {
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := organizationID
	return audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         action,
		ResourceType:   "ip_rule",
		ResourceID:     ruleID,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       meta,
	})
}

// guardEnforced refuses a rule change, inside its transaction, when the rules
// are enforced and the rule set it leaves would refuse the caller.
func (h *Handler) guardEnforced(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID uuid.UUID) error {
	q := h.Service.q.WithTx(tx)
	enabled, err := q.GetIPRulesEnabled(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := q.ListIPRules(ctx, organizationID)
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
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	enabled, err := h.Service.Enabled(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rules, err := h.Service.ListRules(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.ListWith(rules, map[string]any{"enabled": enabled}))
}

func (h *Handler) setConfig(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
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
		rules, err := h.Service.ListRules(ctx, organizationID)
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
	if err := h.Service.SetEnabled(ctx, tx, organizationID, in.Enabled); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, organizationID, nil, "ip_rules.enforcement_changed", map[string]any{"enabled": in.Enabled}); err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
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
	rule, err := h.Service.AddRule(ctx, tx, organizationID, in.CIDR, in.Label, in.Action)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.guardEnforced(ctx, tx, r, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, organizationID, &rule.ID, "ip_rules.rule_added", ruleMetadata(rule)); err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
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
	rule, err := h.Service.DeleteRule(ctx, tx, organizationID, ruleID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.guardEnforced(ctx, tx, r, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, organizationID, &rule.ID, "ip_rules.rule_removed", ruleMetadata(rule)); err != nil {
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
	organizationID, err := httpx.PathOrganization(r)
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
	res, err := h.Service.Check(r.Context(), organizationID, in.IP)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
