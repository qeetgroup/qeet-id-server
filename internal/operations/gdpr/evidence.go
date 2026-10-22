package gdpr

// Compliance evidence for SOC 2 and ISO 27001. Each control maps to a framework
// criterion (CC6.1, A.9.4, …), checks the tenant's live state, and returns pass,
// fail or na with a readable explanation; each run is stored as a
// compliance_evidence_runs row.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ControlStatus is the outcome of one compliance control check.
type ControlStatus string

const (
	ControlPass ControlStatus = "pass" // live data confirmed the condition
	ControlFail ControlStatus = "fail" // live data showed the condition is not met
	ControlNA   ControlStatus = "na"   // the data could not tell, such as no rows yet
)

// ControlResult captures the outcome of one compliance control check.
type ControlResult struct {
	ID       string        `json:"id"`       // stable control ID
	Name     string        `json:"name"`     // display name
	Category string        `json:"category"` // control category
	Criteria string        `json:"criteria"` // framework reference code, such as "CC6.1" or "A.9.4"
	Status   ControlStatus `json:"status"`   // the check's result
	Detail   string        `json:"detail"`   // what was found; never empty
}

// EvidenceRun is one generated evidence snapshot for a tenant+framework pair.
// Controls is populated on GetRun; it is omitted from list responses.
type EvidenceRun struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Framework   string          `json:"framework"`
	GeneratedAt time.Time       `json:"generated_at"`
	GeneratedBy *uuid.UUID      `json:"generated_by,omitempty"`
	PassCount   int             `json:"pass_count"`
	FailCount   int             `json:"fail_count"`
	NACount     int             `json:"na_count"`
	Controls    []ControlResult `json:"controls,omitempty"`
}

// control is a catalog entry: its metadata and a live check. check must return
// ControlPass only when real system data confirms the condition.
type control struct {
	id       string
	name     string
	category string
	criteria string
	check    func(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string)
}

// EvidenceService generates compliance evidence by running live control checks
// against a tenant's system state, and stores the results.
type EvidenceService struct {
	pool          *pgxpool.Pool
	q             *dbgen.Queries
	verifier      *audit.Verifier
	breachEnabled bool
}

// NewEvidenceService returns an EvidenceService. breachEnabled reports whether
// the platform's breached-password (HIBP) check is on, for the control that
// covers it.
func NewEvidenceService(pool *pgxpool.Pool, verifier *audit.Verifier, breachEnabled bool) *EvidenceService {
	return &EvidenceService{pool: pool, q: dbgen.New(pool), verifier: verifier, breachEnabled: breachEnabled}
}

// pgUUIDNullable converts id to a nullable pgtype.UUID; nil becomes NULL.
func pgUUIDNullable(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// toUUIDPtr converts a nullable pgtype.UUID to a *uuid.UUID.
func toUUIDPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// toTimePtr converts a nullable pgtype.Timestamptz to a *time.Time.
func toTimePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// checkMFAEnforcement reports whether sign-in actually enforces a second factor
// for the tenant, not just whether the setting is stored. It fails during the
// grace period after the requirement is turned on, while existing accounts may
// still sign in without one.
func checkMFAEnforcement(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	const notEnforced = "MFA is not enforced: it is optional, so sign-in challenges only people who chose to set up a second factor — set mfa_enforcement to 'required'"
	row, err := svc.q.CheckMFAEnforcement(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlFail, notEnforced + " (no security policy row)"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query security policy: %v", err)
	}
	if row.MfaEnforcement == "optional" {
		return ControlFail, notEnforced
	}
	scope := "every account"
	if row.MfaEnforcement == "admin_only" {
		scope = "administrators (accounts holding a role that grants a write permission)"
	}
	since := ""
	if row.MfaEnforcedSince.Valid {
		since = " since " + row.MfaEnforcedSince.Time.UTC().Format(time.RFC3339)
		until := row.MfaEnforcedSince.Time.Add(time.Duration(row.MfaGraceDays) * 24 * time.Hour)
		if row.MfaGraceDays > 0 && time.Now().Before(until) {
			return ControlFail, fmt.Sprintf("MFA is required of %s but not yet enforced: the grace period runs until %s, and until then accounts that existed when it was turned on may sign in with a password alone",
				scope, until.UTC().Format(time.RFC3339))
		}
	}
	detail := fmt.Sprintf("MFA is enforced at sign-in for %s%s: password sign-in challenges an account holding a second factor, and has one holding none set it up before any session is issued",
		scope, since)
	if row.MfaEnforcement == "required" {
		if without, err := svc.q.CountUsersWithoutSecondFactor(ctx, pgtype.UUID{Bytes: tenantID, Valid: true}); err == nil {
			detail += fmt.Sprintf(" (%d account(s) hold none yet and will set one up at their next sign-in)", without)
		}
	}
	return ControlPass, detail
}

// checkPasswordMinLength checks that the tenant's auth policy requires passwords
// of at least 12 characters.
func checkPasswordMinLength(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	minLen, err := svc.q.CheckPasswordMinLength(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlFail, "no auth policy configured; minimum length defaults to 8 — set to ≥ 12 for compliance"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query auth policy: %v", err)
	}
	if int(minLen) < 12 {
		return ControlFail, fmt.Sprintf("password minimum length is %d; must be ≥ 12 for compliance", minLen)
	}
	return ControlPass, fmt.Sprintf("password minimum length is %d (≥ 12 required)", minLen)
}

// checkPasswordComplexity checks that the uppercase, number and symbol rules are
// all enabled.
func checkPasswordComplexity(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	row, err := svc.q.CheckPasswordComplexity(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlFail, "no auth policy configured; complexity rules default to off — enable uppercase, number, and symbol requirements"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query auth policy: %v", err)
	}
	var missing []string
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
		return ControlFail, "password complexity missing: " + strings.Join(missing, ", ")
	}
	return ControlPass, "password complexity enabled: uppercase, number, and symbol required"
}

// checkSessionTimeout checks that the session max-age is set and at most 24
// hours.
func checkSessionTimeout(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	seconds, err := svc.q.CheckSessionTimeout(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlFail, "no security policy; session max-age defaults to 30 days — set to ≤ 24 hours for compliance"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query session policy: %v", err)
	}
	hours := seconds / 3600
	if seconds > 86400 { // > 24 hours
		return ControlFail, fmt.Sprintf("session max-age is %.1f hours; must be ≤ 24 hours for compliance", hours)
	}
	return ControlPass, fmt.Sprintf("session max-age is %.1f hours (≤ 24 required)", hours)
}

// checkBreachedPasswordAndRisk passes when the tenant has adaptive risk
// settings or the platform's breached-password (HIBP) check is on.
func checkBreachedPasswordAndRisk(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	row, err := svc.q.CheckRiskSettings(ctx, tenantID)
	riskConfigured := !errors.Is(err, pgx.ErrNoRows) && err == nil

	hibpStatus := "disabled"
	if svc.breachEnabled {
		hibpStatus = "enabled"
	}

	if !riskConfigured && !svc.breachEnabled {
		return ControlFail,
			fmt.Sprintf("adaptive risk detection not configured; HIBP breach check is %s — enable at least one protection layer", hibpStatus)
	}
	var parts []string
	if riskConfigured {
		parts = append(parts, fmt.Sprintf("adaptive risk configured (medium threshold %.2f, high %.2f)", row.MediumThreshold, row.HighThreshold))
	}
	parts = append(parts, "HIBP breach check: "+hibpStatus)
	return ControlPass, strings.Join(parts, "; ")
}

// checkRBACRoles checks that the tenant defines RBAC roles.
func checkRBACRoles(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	count, err := svc.q.CheckRBACRoles(ctx, tenantID)
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query RBAC roles: %v", err)
	}
	if count == 0 {
		return ControlFail, "no RBAC roles defined; define roles to implement least-privilege access control"
	}
	return ControlPass, fmt.Sprintf("%d RBAC role(s) defined (least-privilege model active)", count)
}

// checkRBACAssignments checks that users hold roles; with no assignments it
// reports na.
func checkRBACAssignments(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	count, err := svc.q.CheckRBACAssignments(ctx, tenantID)
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query RBAC assignments: %v", err)
	}
	if count == 0 {
		return ControlNA, "no role assignments found; assign roles to users to demonstrate least-privilege access control"
	}
	return ControlPass, fmt.Sprintf("%d role assignment(s) active across tenant users", count)
}

// checkRetentionPolicy checks that a retention policy exists and purges deleted
// users.
func checkRetentionPolicy(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	row, err := svc.q.CheckRetentionPolicy(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlFail, "no retention policy configured; enable deleted-user purge to enforce data disposal"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query retention policy: %v", err)
	}
	if !row.DeletedUsersEnabled {
		return ControlFail, fmt.Sprintf("retention policy exists but deleted-user purge is disabled (window: %d days) — enable it", row.DeletedUsersDays)
	}
	return ControlPass, fmt.Sprintf("data retention enabled: deleted users purged after %d days", row.DeletedUsersDays)
}

// checkIPAccessRules checks that IP rule enforcement is on and at least one
// CIDR rule is defined.
func checkIPAccessRules(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	enabled, err := svc.q.CheckIPRulesConfig(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlNA, "no IP rule configuration found; configure IP allow/deny rules for network boundary protection"
	}
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query IP rules config: %v", err)
	}
	if !enabled {
		return ControlFail, "IP access rules are configured but enforcement is disabled — enable to protect the network boundary"
	}
	ruleCount, _ := svc.q.CheckIPRulesCount(ctx, tenantID)
	if ruleCount == 0 {
		return ControlNA, "IP rule enforcement is enabled but no CIDR rules are defined — add allow/deny rules"
	}
	return ControlPass, fmt.Sprintf("IP access control enforced with %d CIDR rule(s)", ruleCount)
}

// checkSecretsEncryption checks that the tenant stores secrets in the vault,
// which encrypts them with AES-256-GCM; with no secrets it reports na.
func checkSecretsEncryption(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	count, err := svc.q.CheckSecretsCount(ctx, tenantID)
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query secrets vault: %v", err)
	}
	if count == 0 {
		return ControlNA, "no secrets stored in vault yet; the vault (AES-256-GCM, platform key provider) is available but unused — consider storing tenant credentials here"
	}
	return ControlPass, fmt.Sprintf("%d secret(s) stored encrypted at rest (AES-256-GCM, key via platform provider)", count)
}

// checkAuditLogChain verifies the SHA-256 hash chain of the tenant's audit log
// with audit.Verifier. A broken chain means the log was tampered with.
func checkAuditLogChain(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	result, err := svc.verifier.Verify(ctx, &tenantID)
	if err != nil {
		return ControlNA, fmt.Sprintf("could not verify audit chain: %v", err)
	}
	if result.RowsChecked == 0 {
		return ControlNA, "no hash-bearing audit events found; chain verification applies to events recorded after hash-chaining was introduced"
	}
	if !result.OK {
		broken := "unknown"
		if result.BrokenAtID != nil {
			broken = result.BrokenAtID.String()
		}
		return ControlFail, fmt.Sprintf("audit chain broken at event %s: %s (%d rows verified before break)",
			broken, result.BrokenReason, result.RowsChecked)
	}
	return ControlPass, fmt.Sprintf("audit hash chain intact: %d events verified", result.RowsChecked)
}

// checkAuditLogCoverage checks that audit events were recorded in the last 30
// days.
func checkAuditLogCoverage(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	count, err := svc.q.CheckAuditEventCount(ctx, pgtype.UUID{Bytes: tenantID, Valid: true})
	if err != nil {
		return ControlNA, fmt.Sprintf("could not query audit events: %v", err)
	}
	if count == 0 {
		return ControlFail, "no audit events in the last 30 days — audit logging may not be capturing all actions"
	}
	return ControlPass, fmt.Sprintf("%d audit event(s) recorded in the last 30 days", count)
}

// checkSIEMForwarding checks that at least one enabled log sink or active
// webhook subscription forwards events outside the system.
func checkSIEMForwarding(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	sinkCount, _ := svc.q.CheckLogSinksCount(ctx, tenantID)
	webhookCount, _ := svc.q.CheckWebhookSubscriptionsCount(ctx, tenantID)

	if sinkCount == 0 && webhookCount == 0 {
		return ControlFail, "no SIEM log sinks or webhook subscriptions configured; set up log forwarding for external monitoring"
	}
	var parts []string
	if sinkCount > 0 {
		parts = append(parts, fmt.Sprintf("%d active SIEM log sink(s)", sinkCount))
	}
	if webhookCount > 0 {
		parts = append(parts, fmt.Sprintf("%d active webhook subscription(s)", webhookCount))
	}
	return ControlPass, "audit forwarding configured: " + strings.Join(parts, ", ")
}

// checkGDPRProcesses checks that erasure or data-export requests have been
// processed. With none yet it reports na, never a false pass.
func checkGDPRProcesses(ctx context.Context, svc *EvidenceService, tenantID uuid.UUID) (ControlStatus, string) {
	purgeCount, _ := svc.q.CheckPurgeRequestCount(ctx, tenantID)
	exportCount, _ := svc.q.CheckExportRequestCount(ctx, tenantID)

	if purgeCount == 0 && exportCount == 0 {
		return ControlNA, "data-subject rights (right-to-erasure, data portability) are implemented but no requests have been processed for this tenant yet"
	}
	return ControlPass, fmt.Sprintf("data-subject processes operational: %d purge request(s), %d data-export request(s) on record",
		purgeCount, exportCount)
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
		category: "Change Management", criteria: "CC6.5",
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

// iso27001Controls is the ISO/IEC 27001:2013 catalog: 12 controls mapped to
// Annex A controls A.8–A.18.
var iso27001Controls = []control{
	{
		id: "A.9.4-MFA", name: "Multi-Factor Authentication",
		category: "Access Control", criteria: "A.9.4",
		check: checkMFAEnforcement,
	},
	{
		id: "A.9.4.3-PWD-LEN", name: "Password Policy — Minimum Length",
		category: "Access Control", criteria: "A.9.4.3",
		check: checkPasswordMinLength,
	},
	{
		id: "A.9.4.3-PWD-CMPLX", name: "Password Policy — Complexity",
		category: "Access Control", criteria: "A.9.4.3",
		check: checkPasswordComplexity,
	},
	{
		id: "A.9.2-RBAC", name: "User Access Management",
		category: "Access Control", criteria: "A.9.2",
		check: checkRBACRoles,
	},
	{
		id: "A.9.4-SESSION", name: "Session Security Controls",
		category: "Access Control", criteria: "A.9.4",
		check: checkSessionTimeout,
	},
	{
		id: "A.10.1-ENCRYPT", name: "Cryptographic Controls — Secrets Vault",
		category: "Cryptography", criteria: "A.10.1",
		check: checkSecretsEncryption,
	},
	{
		id: "A.12.4.1-AUDIT", name: "Audit Log Coverage",
		category: "Operations Security", criteria: "A.12.4.1",
		check: checkAuditLogCoverage,
	},
	{
		id: "A.12.4.2-CHAIN", name: "Audit Log Integrity",
		category: "Operations Security", criteria: "A.12.4.2",
		check: checkAuditLogChain,
	},
	{
		id: "A.12.4.3-SIEM", name: "Log Forwarding and SIEM Integration",
		category: "Operations Security", criteria: "A.12.4.3",
		check: checkSIEMForwarding,
	},
	{
		id: "A.13.1-IP", name: "Network Access Controls",
		category: "Communications Security", criteria: "A.13.1",
		check: checkIPAccessRules,
	},
	{
		id: "A.18.1-GDPR", name: "Privacy and Data-Subject Processes",
		category: "Compliance", criteria: "A.18.1",
		check: checkGDPRProcesses,
	},
	{
		id: "A.8.3-RETAIN", name: "Data Retention and Disposal",
		category: "Asset Management", criteria: "A.8.3",
		check: checkRetentionPolicy,
	},
}

// controlsByFramework maps a framework name to its control catalog.
var controlsByFramework = map[string][]control{
	"soc2":     soc2Controls,
	"iso27001": iso27001Controls,
}

// ValidFramework reports whether the framework name is supported.
func ValidFramework(f string) bool {
	_, ok := controlsByFramework[f]
	return ok
}

// Generate runs every control of framework against the tenant's live state and
// stores the run, with an audit event, in one transaction. It returns the run
// with its control results.
func (s *EvidenceService) Generate(ctx context.Context, tenantID uuid.UUID, framework string, actor *uuid.UUID) (*EvidenceRun, error) {
	controls, ok := controlsByFramework[framework]
	if !ok {
		return nil, errs.ErrGDPRFrameworkInvalid
	}

	results := make([]ControlResult, 0, len(controls))
	var passCount, failCount, naCount int
	for _, c := range controls {
		status, detail := c.check(ctx, s, tenantID)
		results = append(results, ControlResult{
			ID:       c.id,
			Name:     c.name,
			Category: c.category,
			Criteria: c.criteria,
			Status:   status,
			Detail:   detail,
		})
		switch status {
		case ControlPass:
			passCount++
		case ControlFail:
			failCount++
		default:
			naCount++
		}
	}

	controlsJSON, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	// Store the run and its audit event in one transaction.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := dbgen.New(tx).InsertEvidenceRun(ctx, dbgen.InsertEvidenceRunParams{
		TenantID:    tenantID,
		Framework:   framework,
		GeneratedBy: pgUUIDNullable(actor),
		PassCount:   int32(passCount),
		FailCount:   int32(failCount),
		NaCount:     int32(naCount),
		Controls:    controlsJSON,
	})
	if err != nil {
		return nil, err
	}

	run := EvidenceRun{
		ID:          row.ID,
		TenantID:    row.TenantID,
		Framework:   row.Framework,
		GeneratedAt: row.GeneratedAt,
		GeneratedBy: toUUIDPtr(row.GeneratedBy),
		PassCount:   int(row.PassCount),
		FailCount:   int(row.FailCount),
		NACount:     int(row.NaCount),
	}

	rid := run.ID
	tid := tenantID
	actorType := "system"
	if actor != nil {
		actorType = "user"
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actor,
		ActorType:    actorType,
		Action:       "compliance.evidence_generated",
		ResourceType: "compliance_evidence_run",
		ResourceID:   &rid,
		Metadata: map[string]any{
			"framework":  framework,
			"pass_count": passCount,
			"fail_count": failCount,
			"na_count":   naCount,
		},
	}); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	run.Controls = results
	return &run, nil
}

// ListRuns returns the tenant's 100 most recent runs of framework, newest
// first, without their controls; GetRun has the full report.
func (s *EvidenceService) ListRuns(ctx context.Context, tenantID uuid.UUID, framework string) ([]EvidenceRun, error) {
	rows, err := s.q.ListEvidenceRuns(ctx, dbgen.ListEvidenceRunsParams{
		TenantID:  tenantID,
		Framework: framework,
	})
	if err != nil {
		return nil, err
	}
	out := make([]EvidenceRun, 0, len(rows))
	for _, r := range rows {
		out = append(out, EvidenceRun{
			ID:          r.ID,
			TenantID:    r.TenantID,
			Framework:   r.Framework,
			GeneratedAt: r.GeneratedAt,
			GeneratedBy: toUUIDPtr(r.GeneratedBy),
			PassCount:   int(r.PassCount),
			FailCount:   int(r.FailCount),
			NACount:     int(r.NaCount),
		})
	}
	return out, nil
}

// GetRun returns one of the tenant's evidence runs with its control results:
// the full evidence report.
func (s *EvidenceService) GetRun(ctx context.Context, tenantID, id uuid.UUID) (*EvidenceRun, error) {
	r, err := s.q.GetEvidenceRun(ctx, dbgen.GetEvidenceRunParams{
		ID:       id,
		TenantID: tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	run := &EvidenceRun{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Framework:   r.Framework,
		GeneratedAt: r.GeneratedAt,
		GeneratedBy: toUUIDPtr(r.GeneratedBy),
		PassCount:   int(r.PassCount),
		FailCount:   int(r.FailCount),
		NACount:     int(r.NaCount),
	}
	if len(r.Controls) > 0 {
		if err := json.Unmarshal(r.Controls, &run.Controls); err != nil {
			return nil, err
		}
	}
	return run, nil
}

// requireEvidencePathTenant returns the {tenantID} path parameter if it matches
// the caller's tenant. httpx.EnforceTenantScope is the primary guard; this is
// defence in depth.
func requireEvidencePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrGDPRTenantInvalid
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrGDPRTenantMismatch
	}
	return scope, nil
}

// validEvidenceFramework returns the {framework} path parameter, or
// errs.ErrGDPRFrameworkInvalid if it is not supported.
func validEvidenceFramework(r *http.Request) (string, error) {
	f := chi.URLParam(r, "framework")
	if f != "soc2" && f != "iso27001" {
		return "", errs.ErrGDPRFrameworkInvalid
	}
	return f, nil
}

// generateEvidence serves POST /tenants/{tenantID}/compliance/{framework}/evidence:
// it runs the framework's controls and returns the full run.
func (h *Handler) generateEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	framework, err := validEvidenceFramework(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actor *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		actor = p.UserID
	}
	run, err := h.Evidence.Generate(r.Context(), tid, framework, actor)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, run)
}

// listEvidence serves GET /tenants/{tenantID}/compliance/{framework}/evidence:
// the framework's previous runs, newest first, without controls.
func (h *Handler) listEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	framework, err := validEvidenceFramework(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.ListRuns(r.Context(), tid, framework)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// getEvidence serves GET /tenants/{tenantID}/compliance/evidence/{id}: the full
// run, with a Content-Disposition header so it downloads as a report.
func (h *Handler) getEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRIDInvalid)
		return
	}
	run, err := h.Evidence.GetRun(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition",
		`attachment; filename="evidence-`+run.Framework+`-`+run.ID.String()+`.json"`)
	httpx.WriteJSON(w, http.StatusOK, run)
}

// mountEvidence registers the evidence routes.
func (h *Handler) mountEvidence(r chi.Router) {
	r.Post("/tenants/{tenantID}/compliance/{framework}/evidence", h.generateEvidence)
	r.Get("/tenants/{tenantID}/compliance/{framework}/evidence", h.listEvidence)
	r.Get("/tenants/{tenantID}/compliance/evidence/{id}", h.getEvidence)
}

// EvidenceRunCount returns the number of evidence runs of a tenant across all
// frameworks.
func (s *EvidenceService) EvidenceRunCount(ctx context.Context, tenantID uuid.UUID) (int, error) {
	n, err := s.q.CountEvidenceRuns(ctx, tenantID)
	return int(n), err
}

// TotalControls returns the number of controls in a framework's catalog, or 0
// for an unknown framework.
func TotalControls(framework string) int {
	return len(controlsByFramework[framework])
}

// tallyResults counts the pass, fail and na results.
func tallyResults(results []ControlResult) (pass, fail, na int) {
	for _, r := range results {
		switch r.Status {
		case ControlPass:
			pass++
		case ControlFail:
			fail++
		default:
			na++
		}
	}
	return
}
