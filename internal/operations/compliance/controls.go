package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// control is a catalog entry: its metadata and a live check. check must return
// ControlPass only when real system data confirms the condition.
type control struct {
	id           string
	name         string
	category     string
	criteria     string
	criteria2013 string // ISO/IEC 27001:2013 Annex A, for an ISO control
	check        func(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding
}

// finding is what one check found: its status, in words, and the same as a
// code with parameters a console can word itself. A failing finding's code
// names its remedy too (remedies).
type finding struct {
	status ControlStatus
	code   string
	params map[string]any
	detail string
}

// found is a finding of status, code and params, worded as detail.
func found(status ControlStatus, code string, params map[string]any, detail string) finding {
	return finding{status: status, code: code, params: params, detail: detail}
}

// unreadable is the na finding of a check whose data couldn't be read.
func unreadable(what string, err error) finding {
	return found(ControlNA, "evidence.unreadable", map[string]any{"source": what}, fmt.Sprintf("could not query %s: %v", what, err))
}

// remedies maps a failing finding's code to what would make it pass.
var remedies = map[string]string{
	"mfa.not_enforced":          "require_mfa",
	"mfa.in_grace_period":       "wait_for_mfa_grace_period",
	"password_length.too_short": "raise_password_min_length",
	"password_complexity.weak":  "require_password_complexity",
	"session.too_long":          "shorten_session_max_age",
	"breach.unprotected":        "enable_risk_or_breach_check",
	"rbac.no_roles":             "define_roles",
	"retention.not_configured":  "enable_retention_purge",
	"retention.purge_disabled":  "enable_retention_purge",
	"ip_rules.not_enforced":     "enable_ip_rules",
	"audit_chain.broken":        "investigate_audit_chain",
	"audit_coverage.none":       "check_audit_logging",
	"siem.no_sinks":             "add_log_sink",
	"siem.not_delivering":       "fix_log_sink",
}

// checkMFAEnforcement reports whether sign-in actually enforces a second factor
// for the organization, not just whether the setting is stored. It fails during the
// grace period after the requirement is turned on, while existing accounts may
// still sign in without one.
func checkMFAEnforcement(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	const notEnforced = "MFA is not enforced: it is optional, so sign-in challenges only people who chose to set up a second factor — set mfa_enforcement to 'required'"
	row, err := svc.q.CheckMFAEnforcement(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlFail, "mfa.not_enforced", map[string]any{"mfa_enforcement": "optional"}, notEnforced+" (no security policy row)")
	}
	if err != nil {
		return unreadable("security policy", err)
	}
	if row.MfaEnforcement == "optional" {
		return found(ControlFail, "mfa.not_enforced", map[string]any{"mfa_enforcement": "optional"}, notEnforced)
	}
	scope := "every account"
	if row.MfaEnforcement == "admin_only" {
		scope = "administrators (accounts holding a role that grants a write permission)"
	}
	params := map[string]any{"mfa_enforcement": row.MfaEnforcement}
	since := ""
	if row.MfaEnforcedSince != nil {
		since = " since " + row.MfaEnforcedSince.UTC().Format(time.RFC3339)
		params["enforced_since"] = row.MfaEnforcedSince.UTC()
		until := row.MfaEnforcedSince.Add(time.Duration(row.MfaGraceDays) * 24 * time.Hour)
		if row.MfaGraceDays > 0 && time.Now().Before(until) {
			params["grace_until"] = until.UTC()
			return found(ControlFail, "mfa.in_grace_period", params, fmt.Sprintf("MFA is required of %s but not yet enforced: the grace period runs until %s, and until then accounts that existed when it was turned on may sign in with a password alone",
				scope, until.UTC().Format(time.RFC3339)))
		}
	}
	detail := fmt.Sprintf("MFA is enforced at sign-in for %s%s: password sign-in challenges an account holding a second factor, and has one holding none set it up before any session is issued",
		scope, since)
	if row.MfaEnforcement == "required" {
		if without, err := svc.q.CountUsersWithoutSecondFactor(ctx, &organizationID); err == nil {
			params["accounts_without_factor"] = without
			detail += fmt.Sprintf(" (%d account(s) hold none yet and will set one up at their next sign-in)", without)
		}
	}
	return found(ControlPass, "mfa.enforced", params, detail)
}

// checkPasswordMinLength checks that the organization's auth policy requires passwords
// of at least 12 characters.
func checkPasswordMinLength(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	minLen, err := svc.q.CheckPasswordMinLength(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlFail, "password_length.too_short", map[string]any{"min_length": 8, "required": 12},
			"no auth policy configured; minimum length defaults to 8 — set to ≥ 12 for compliance")
	}
	if err != nil {
		return unreadable("auth policy", err)
	}
	params := map[string]any{"min_length": minLen, "required": 12}
	if int(minLen) < 12 {
		return found(ControlFail, "password_length.too_short", params, fmt.Sprintf("password minimum length is %d; must be ≥ 12 for compliance", minLen))
	}
	return found(ControlPass, "password_length.sufficient", params, fmt.Sprintf("password minimum length is %d (≥ 12 required)", minLen))
}

// checkPasswordComplexity checks that the uppercase, number and symbol rules are
// all enabled.
func checkPasswordComplexity(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	row, err := svc.q.CheckPasswordComplexity(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlFail, "password_complexity.weak", map[string]any{"missing": []string{"uppercase", "number", "symbol"}},
			"no auth policy configured; complexity rules default to off — enable uppercase, number, and symbol requirements")
	}
	if err != nil {
		return unreadable("auth policy", err)
	}
	missing := []string{}
	if !row.PasswordRequireUppercase {
		missing = append(missing, "uppercase")
	}
	if !row.PasswordRequireNumber {
		missing = append(missing, "number")
	}
	if !row.PasswordRequireSymbol {
		missing = append(missing, "symbol")
	}
	if len(missing) > 0 {
		return found(ControlFail, "password_complexity.weak", map[string]any{"missing": missing}, "password complexity missing: "+strings.Join(missing, ", "))
	}
	return found(ControlPass, "password_complexity.required", nil, "password complexity enabled: uppercase, number, and symbol required")
}

// checkSessionTimeout checks that the session max-age is set and at most 24
// hours.
func checkSessionTimeout(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	seconds, err := svc.q.CheckSessionTimeout(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlFail, "session.too_long", map[string]any{"max_age_hours": 720, "required_hours": 24},
			"no security policy; session max-age defaults to 30 days — set to ≤ 24 hours for compliance")
	}
	if err != nil {
		return unreadable("session policy", err)
	}
	hours := seconds / 3600
	params := map[string]any{"max_age_hours": hours, "required_hours": 24}
	if seconds > 86400 { // > 24 hours
		return found(ControlFail, "session.too_long", params, fmt.Sprintf("session max-age is %.1f hours; must be ≤ 24 hours for compliance", hours))
	}
	return found(ControlPass, "session.bounded", params, fmt.Sprintf("session max-age is %.1f hours (≤ 24 required)", hours))
}

// checkBreachedPasswordAndRisk passes when the organization has adaptive risk
// settings or the platform's breached-password (HIBP) check is on.
func checkBreachedPasswordAndRisk(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	row, err := svc.q.CheckRiskSettings(ctx, organizationID)
	riskConfigured := !errors.Is(err, pgx.ErrNoRows) && err == nil

	hibpStatus := "disabled"
	if svc.breachEnabled {
		hibpStatus = "enabled"
	}
	params := map[string]any{"risk_configured": riskConfigured, "breach_check": svc.breachEnabled}
	if !riskConfigured && !svc.breachEnabled {
		return found(ControlFail, "breach.unprotected", params,
			fmt.Sprintf("adaptive risk detection not configured; HIBP breach check is %s — enable at least one protection layer", hibpStatus))
	}
	var parts []string
	if riskConfigured {
		params["medium_threshold"], params["high_threshold"] = row.MediumThreshold, row.HighThreshold
		parts = append(parts, fmt.Sprintf("adaptive risk configured (medium threshold %.2f, high %.2f)", row.MediumThreshold, row.HighThreshold))
	}
	parts = append(parts, "HIBP breach check: "+hibpStatus)
	return found(ControlPass, "breach.protected", params, strings.Join(parts, "; "))
}

// checkRBACRoles checks that the organization defines RBAC roles.
func checkRBACRoles(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	count, err := svc.q.CheckRBACRoles(ctx, organizationID)
	if err != nil {
		return unreadable("RBAC roles", err)
	}
	if count == 0 {
		return found(ControlFail, "rbac.no_roles", nil, "no RBAC roles defined; define roles to implement least-privilege access control")
	}
	return found(ControlPass, "rbac.roles_defined", map[string]any{"roles": count}, fmt.Sprintf("%d RBAC role(s) defined (least-privilege model active)", count))
}

// checkRBACAssignments checks that users hold roles; with no assignments it
// reports na.
func checkRBACAssignments(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	count, err := svc.q.CheckRBACAssignments(ctx, organizationID)
	if err != nil {
		return unreadable("RBAC assignments", err)
	}
	if count == 0 {
		return found(ControlNA, "rbac.no_assignments", nil, "no role assignments found; assign roles to users to demonstrate least-privilege access control")
	}
	return found(ControlPass, "rbac.assigned", map[string]any{"assignments": count}, fmt.Sprintf("%d role assignment(s) active across organization users", count))
}

// checkRetentionPolicy checks that a retention policy exists and purges deleted
// users.
func checkRetentionPolicy(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	row, err := svc.q.CheckRetentionPolicy(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlFail, "retention.not_configured", nil, "no retention policy configured; enable deleted-user purge to enforce data disposal")
	}
	if err != nil {
		return unreadable("retention policy", err)
	}
	params := map[string]any{"days": row.DeletedUsersDays}
	if !row.DeletedUsersEnabled {
		return found(ControlFail, "retention.purge_disabled", params, fmt.Sprintf("retention policy exists but deleted-user purge is disabled (window: %d days) — enable it", row.DeletedUsersDays))
	}
	return found(ControlPass, "retention.enabled", params, fmt.Sprintf("data retention enabled: deleted users purged after %d days", row.DeletedUsersDays))
}

// checkIPAccessRules checks that IP rule enforcement is on and at least one
// CIDR rule is defined.
func checkIPAccessRules(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	enabled, err := svc.q.CheckIPRulesConfig(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return found(ControlNA, "ip_rules.not_configured", nil, "no IP rule configuration found; configure IP allow/deny rules for network boundary protection")
	}
	if err != nil {
		return unreadable("IP rules config", err)
	}
	if !enabled {
		return found(ControlFail, "ip_rules.not_enforced", nil, "IP access rules are configured but enforcement is disabled — enable to protect the network boundary")
	}
	ruleCount, _ := svc.q.CheckIPRulesCount(ctx, organizationID)
	if ruleCount == 0 {
		return found(ControlNA, "ip_rules.no_rules", nil, "IP rule enforcement is enabled but no CIDR rules are defined — add allow/deny rules")
	}
	return found(ControlPass, "ip_rules.enforced", map[string]any{"rules": ruleCount}, fmt.Sprintf("IP access control enforced with %d CIDR rule(s)", ruleCount))
}

// checkSecretsEncryption checks that the organization stores secrets in the vault,
// which encrypts them with AES-256-GCM; with no secrets it reports na.
func checkSecretsEncryption(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	count, err := svc.q.CheckSecretsCount(ctx, organizationID)
	if err != nil {
		return unreadable("secrets vault", err)
	}
	if count == 0 {
		return found(ControlNA, "secrets.unused", nil, "no secrets stored in vault yet; the vault (AES-256-GCM, platform key provider) is available but unused — consider storing organization credentials here")
	}
	return found(ControlPass, "secrets.encrypted", map[string]any{"secrets": count}, fmt.Sprintf("%d secret(s) stored encrypted at rest (AES-256-GCM, key via platform provider)", count))
}

// checkAuditLogChain verifies the SHA-256 hash chain of the organization's audit log
// with audit.Verifier. A broken chain means the log was tampered with.
func checkAuditLogChain(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	result, err := svc.verifier.Verify(ctx, &organizationID)
	if err != nil {
		return found(ControlNA, "audit_chain.unverifiable", nil, fmt.Sprintf("could not verify audit chain: %v", err))
	}
	if result.RowsChecked == 0 {
		return found(ControlNA, "audit_chain.empty", nil, "no hash-bearing audit events found; chain verification applies to events recorded after hash-chaining was introduced")
	}
	if !result.OK {
		broken := "unknown"
		if result.BrokenAtID != nil {
			broken = result.BrokenAtID.String()
		}
		return found(ControlFail, "audit_chain.broken",
			map[string]any{"broken_at": broken, "reason_code": result.ReasonCode, "rows_checked": result.RowsChecked},
			fmt.Sprintf("audit chain broken at event %s: %s (%d rows verified before break)", broken, result.BrokenReason, result.RowsChecked))
	}
	return found(ControlPass, "audit_chain.intact", map[string]any{"rows_checked": result.RowsChecked}, fmt.Sprintf("audit hash chain intact: %d events verified", result.RowsChecked))
}

// checkAuditLogCoverage checks that audit events were recorded in the last 30
// days.
func checkAuditLogCoverage(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	count, err := svc.q.CheckAuditEventCount(ctx, &organizationID)
	if err != nil {
		return unreadable("audit events", err)
	}
	if count == 0 {
		return found(ControlFail, "audit_coverage.none", map[string]any{"days": 30}, "no audit events in the last 30 days — audit logging may not be capturing all actions")
	}
	return found(ControlPass, "audit_coverage.recorded", map[string]any{"days": 30, "events": count}, fmt.Sprintf("%d audit event(s) recorded in the last 30 days", count))
}

// checkSIEMForwarding checks that a log sink is delivering the audit log
// outside the system: enabled, forwarded within a day and not failing. A
// webhook subscription doesn't count, as webhooks don't carry the audit log.
func checkSIEMForwarding(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	sinks, err := svc.q.CheckLogSinksCount(ctx, organizationID)
	if err != nil {
		return found(ControlFail, "siem.unreadable", nil, "the log sinks could not be read")
	}
	params := map[string]any{"enabled": sinks.Enabled, "delivering": sinks.Delivering}
	switch {
	case sinks.Enabled == 0:
		return found(ControlFail, "siem.no_sinks", params, "no SIEM log sinks configured; set up log forwarding for external monitoring")
	case sinks.Delivering == 0:
		return found(ControlFail, "siem.not_delivering", params, fmt.Sprintf("%d SIEM log sink(s) configured, none delivered in the last day or all are failing", sinks.Enabled))
	}
	return found(ControlPass, "siem.delivering", params, fmt.Sprintf("audit forwarding delivering to %d of %d SIEM log sink(s)", sinks.Delivering, sinks.Enabled))
}

// checkGDPRProcesses checks that erasure or data-export requests have been
// processed. With none yet it reports na, never a false pass.
func checkGDPRProcesses(ctx context.Context, svc *EvidenceService, organizationID uuid.UUID) finding {
	purgeCount, _ := svc.q.CheckPurgeRequestCount(ctx, organizationID)
	exportCount, _ := svc.q.CheckExportRequestCount(ctx, organizationID)
	params := map[string]any{"erasure_requests": purgeCount, "export_requests": exportCount}
	if purgeCount == 0 && exportCount == 0 {
		return found(ControlNA, "gdpr.no_requests", params, "data-subject rights (right-to-erasure, data portability) are implemented but no requests have been processed for this organization yet")
	}
	return found(ControlPass, "gdpr.operational", params, fmt.Sprintf("data-subject processes operational: %d purge request(s), %d data-export request(s) on record",
		purgeCount, exportCount))
}

// soc2Controls is the SOC 2 Type II catalog: 13 controls mapped to AICPA Trust
// Services Criteria CC6.1–CC7.2.
var soc2Controls = []control{
	{
		id: "CC6.1-MFA", name: "Multi-Factor Authentication Enforcement",
		category: "Logical and Physical Access Controls", criteria: "CC6.1",
		check: checkMFAEnforcement,
	},
	{
		id: "CC6.1-PWD-LEN", name: "Password Minimum Length",
		category: "Logical and Physical Access Controls", criteria: "CC6.1",
		check: checkPasswordMinLength,
	},
	{
		id: "CC6.1-PWD-CMPLX", name: "Password Complexity Requirements",
		category: "Logical and Physical Access Controls", criteria: "CC6.1",
		check: checkPasswordComplexity,
	},
	{
		id: "CC6.1-SESSION", name: "Session Timeout",
		category: "Logical and Physical Access Controls", criteria: "CC6.1",
		check: checkSessionTimeout,
	},
	{
		id: "CC6.1-BREACH", name: "Breached Password and Adaptive Risk Detection",
		category: "Logical and Physical Access Controls", criteria: "CC6.1",
		check: checkBreachedPasswordAndRisk,
	},
	{
		id: "CC6.3-RBAC-ROLES", name: "RBAC Role Definitions",
		category: "Logical and Physical Access Controls", criteria: "CC6.3",
		check: checkRBACRoles,
	},
	{
		id: "CC6.3-RBAC-ASSIGN", name: "RBAC Role Assignments",
		category: "Logical and Physical Access Controls", criteria: "CC6.3",
		check: checkRBACAssignments,
	},
	{
		id: "CC6.5-RETAIN", name: "Data Retention and Disposal",
		category: "Logical and Physical Access Controls", criteria: "CC6.5",
		check: checkRetentionPolicy,
	},
	{
		id: "CC6.6-IP-ACL", name: "Network Access Controls",
		category: "Logical and Physical Access Controls", criteria: "CC6.6",
		check: checkIPAccessRules,
	},
	{
		id: "CC6.7-SECRETS", name: "Secrets Encryption at Rest",
		category: "Logical and Physical Access Controls", criteria: "CC6.7",
		check: checkSecretsEncryption,
	},
	{
		id: "CC7.2-CHAIN", name: "Audit Log Tamper-Evidence",
		category: "System Monitoring", criteria: "CC7.2",
		check: checkAuditLogChain,
	},
	{
		id: "CC7.2-ACTIVE", name: "Audit Log Coverage",
		category: "System Monitoring", criteria: "CC7.2",
		check: checkAuditLogCoverage,
	},
	{
		id: "CC7.2-SIEM", name: "SIEM and Log Forwarding",
		category: "System Monitoring", criteria: "CC7.2",
		check: checkSIEMForwarding,
	},
}

// iso27001Controls is the ISO/IEC 27001:2022 catalog: 12 controls mapped to
// Annex A organizational (A.5) and technological (A.8) controls, each with its
// 2013 reference. IDs keep their first names so stored runs still line up.
var iso27001Controls = []control{
	{
		id: "A.9.4-MFA", name: "Multi-Factor Authentication",
		category: "Technological controls", criteria: "A.8.5", criteria2013: "A.9.4",
		check: checkMFAEnforcement,
	},
	{
		id: "A.9.4.3-PWD-LEN", name: "Password Policy — Minimum Length",
		category: "Organizational controls", criteria: "A.5.17", criteria2013: "A.9.4.3",
		check: checkPasswordMinLength,
	},
	{
		id: "A.9.4.3-PWD-CMPLX", name: "Password Policy — Complexity",
		category: "Organizational controls", criteria: "A.5.17", criteria2013: "A.9.4.3",
		check: checkPasswordComplexity,
	},
	{
		id: "A.9.2-RBAC", name: "User Access Management",
		category: "Organizational controls", criteria: "A.5.18", criteria2013: "A.9.2",
		check: checkRBACRoles,
	},
	{
		id: "A.9.4-SESSION", name: "Session Security Controls",
		category: "Technological controls", criteria: "A.8.5", criteria2013: "A.9.4",
		check: checkSessionTimeout,
	},
	{
		id: "A.10.1-ENCRYPT", name: "Cryptographic Controls — Secrets Vault",
		category: "Technological controls", criteria: "A.8.24", criteria2013: "A.10.1",
		check: checkSecretsEncryption,
	},
	{
		id: "A.12.4.1-AUDIT", name: "Audit Log Coverage",
		category: "Technological controls", criteria: "A.8.15", criteria2013: "A.12.4.1",
		check: checkAuditLogCoverage,
	},
	{
		id: "A.12.4.2-CHAIN", name: "Audit Log Integrity",
		category: "Technological controls", criteria: "A.8.15", criteria2013: "A.12.4.2",
		check: checkAuditLogChain,
	},
	{
		id: "A.12.4.3-SIEM", name: "Log Forwarding and SIEM Integration",
		category: "Technological controls", criteria: "A.8.16", criteria2013: "A.12.4.3",
		check: checkSIEMForwarding,
	},
	{
		id: "A.13.1-IP", name: "Network Access Controls",
		category: "Technological controls", criteria: "A.8.20", criteria2013: "A.13.1",
		check: checkIPAccessRules,
	},
	{
		id: "A.18.1-GDPR", name: "Privacy and Data-Subject Processes",
		category: "Organizational controls", criteria: "A.5.34", criteria2013: "A.18.1",
		check: checkGDPRProcesses,
	},
	{
		id: "A.8.3-RETAIN", name: "Data Retention and Disposal",
		category: "Technological controls", criteria: "A.8.10", criteria2013: "A.8.3",
		check: checkRetentionPolicy,
	},
}

// controlsByFramework maps a framework name to its control catalog.
var controlsByFramework = map[string][]control{
	"soc2":     soc2Controls,
	"iso27001": iso27001Controls,
}
