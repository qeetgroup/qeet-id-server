// Package ipallow manages per-organization IP allow and deny rules (CIDRs). Deny
// rules win, and if any allow rule exists an address must match one. Rules are
// enforced only while the organization's flag is on; then every sign-in to the
// organization and every session renewal in it calls CheckSignIn.
package ipallow

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Rule is an organization address rule: CIDR is allowed or denied according to
// Action ("allow" or "deny").
type Rule struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
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

// CheckResult is what Check makes of an address. ReasonCode is "ip." and the Decision.Reason, or
// CodeEnforcementOff; Reason is the same in English; ReasonParams names a refusing rule's CIDR. Rules
// is what the rules decide whatever the enforcement flag, so they can be tried before they're on.
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

// SetEnabled turns the organization's address rules on or off, recorded as
// actor's. Turning them on is refused, with ErrRiskRulesLockOutCaller, when
// they would refuse actor's own address, so an organization can't lock its
// admins out.
func (s *Service) SetEnabled(ctx context.Context, organizationID uuid.UUID, enabled bool, actor audit.Actor) error {
	if enabled {
		rules, err := s.ListRules(ctx, organizationID)
		if err != nil {
			return err
		}
		if err := refusesCaller(rules, actor.IP); err != nil {
			return err
		}
	}
	_, err := s.auditedChange(ctx, organizationID, actor, "ip_rules.enforcement_changed", func(q *dbgen.Queries) (*Rule, map[string]any, error) {
		err := q.SetIPRulesEnabled(ctx, dbgen.SetIPRulesEnabledParams{OrganizationID: organizationID, Enabled: enabled})
		return nil, map[string]any{"enabled": enabled}, err
	})
	return err
}

// AddRule adds an allow or deny rule for a CIDR range to the organization,
// recorded as actor's. No action means allow; any other action is refused, so
// a mistyped deny never allows. While the rules are enforced, a rule that
// would refuse actor's own address is refused with ErrRiskRulesLockOutCaller.
func (s *Service) AddRule(ctx context.Context, organizationID uuid.UUID, cidr, label, action string, actor audit.Actor) (*Rule, error) {
	if _, err := parsePrefix(cidr); err != nil {
		return nil, ErrRiskCIDRInvalid
	}
	switch action {
	case "":
		action = "allow"
	case "allow", "deny":
	default:
		return nil, ErrRiskRuleActionInvalid
	}
	return s.auditedChange(ctx, organizationID, actor, "ip_rules.rule_added", func(q *dbgen.Queries) (*Rule, map[string]any, error) {
		m, err := q.InsertIPRule(ctx, dbgen.InsertIPRuleParams{
			OrganizationID: organizationID,
			Cidr:           strings.TrimSpace(cidr),
			Label:          label,
			Action:         action,
		})
		if err != nil {
			return nil, nil, err
		}
		r := ruleFromModel(m)
		return &r, ruleMetadata(&r), nil
	})
}

// DeleteRule removes one of the organization's address rules, recorded as
// actor's, and returns it. While the rules are enforced, a removal that would
// leave them refusing actor's own address is refused with
// ErrRiskRulesLockOutCaller.
func (s *Service) DeleteRule(ctx context.Context, organizationID, ruleID uuid.UUID, actor audit.Actor) (*Rule, error) {
	return s.auditedChange(ctx, organizationID, actor, "ip_rules.rule_removed", func(q *dbgen.Queries) (*Rule, map[string]any, error) {
		m, err := q.DeleteIPRule(ctx, dbgen.DeleteIPRuleParams{ID: ruleID, OrganizationID: organizationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errs.ErrNotFound
		}
		if err != nil {
			return nil, nil, err
		}
		r := ruleFromModel(m)
		return &r, ruleMetadata(&r), nil
	})
}

// auditedChange runs edit, a change to the organization's rules, in one
// transaction with its audit record of action: edit returns the rule it
// changed (nil: none) and what to record of it. A change that leaves enforced
// rules refusing actor's own address is rolled back.
func (s *Service) auditedChange(ctx context.Context, organizationID uuid.UUID, actor audit.Actor, action string,
	edit func(q *dbgen.Queries) (*Rule, map[string]any, error)) (*Rule, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	rule, meta, err := edit(q)
	if err != nil {
		return nil, err
	}
	var ruleID uuid.UUID
	if rule != nil {
		ruleID = rule.ID
		if err := guardEnforced(ctx, q, organizationID, actor.IP); err != nil {
			return nil, err
		}
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "ip_rule", ruleID, meta)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rule, nil
}

// guardEnforced refuses a rule change, read through its transaction's q, when
// the rules are enforced and the rule set it leaves would refuse caller.
func guardEnforced(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, caller string) error {
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
	return refusesCaller(rules, caller)
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

// AddressPolicy applies an organization's address rules to a sign-in: CheckSignIn
// returns errs.ErrAuthAddressNotAllowed, after recording the refusal, when ip may
// not sign in to organizationID; CheckSignInTx does so through tx, recording the
// refusal there for the caller to commit. Satisfied by *Service.
type AddressPolicy interface {
	CheckSignIn(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error
	CheckSignInTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error
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
	if err := audit.RecordAlone(ctx, s.pool, refusalEvent(organizationID, userID, ip, path, d)); err != nil {
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
	var ruleID uuid.UUID
	if d.Rule != nil {
		ruleID = d.Rule.ID
		meta["rule_id"] = ruleID
		meta["cidr"] = d.Rule.CIDR
	}
	// The address column takes only a readable address; an unreadable one is
	// kept in the metadata alone.
	by := audit.Actor{UserID: postgres.NullIfZero(userID), Type: "user", IP: ip}
	if d.Reason == ReasonUnknownAddr {
		by.IP = ""
	}
	return by.Event(organizationID, "auth.address_refused", "ip_rule", ruleID, meta)
}

// refusesCaller returns ErrRiskRulesLockOutCaller if rules would refuse the
// caller's own address (httpx.ClientIP), so an organization can't lock its
// admins out. For the console, that is the console server's address.
func refusesCaller(rules []Rule, caller string) error {
	if d := Decide(rules, caller); !d.Allowed {
		return ErrRiskRulesLockOutCaller.WithDetail("your address as the API sees it: " + caller)
	}
	return nil
}

// ruleMetadata is what an audit event says of the rule it changed.
func ruleMetadata(rule *Rule) map[string]any {
	return map[string]any{"cidr": rule.CIDR, "action": rule.Action, "label": rule.Label}
}
