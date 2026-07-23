// Package activity provides the Live Activity backend: a tenant-filtered SSE
// stream (live, from the NATS outbox) and a cursor-paginated history endpoint
// (from the hash-chained audit.events table). Raw-event to ActivityEvent mapping
// is centralised here so live and history present a consistent view.
package activity

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Severity values mirror common log/security conventions and match the
// frontend ActivityEvent severity discriminant.
const (
	SeverityInfo     = "info"
	SeveritySuccess  = "success"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// Category groups event types into coarse operational domains shown in the
// console activity filter pill.
const (
	CategoryAuthentication = "authentication"
	CategoryAuthorization  = "authorization"
	CategorySecurity       = "security"
	CategoryDirectory      = "directory"
	CategoryDeveloper      = "developer"
	CategorySystem         = "system"
)

// ActivityEvent is the unified wire representation of a domain event, whether
// sourced from the live NATS outbox stream or the durable audit log.
//
// TenantID is populated by both mapOutboxEvent and mapAuditRow. The SSE stream
// handler uses it as a defense-in-depth guard: any event whose TenantID does
// not match the authenticated connection's tenant is dropped before the SSE
// write, catching any hub mis-routing before it becomes a cross-tenant leak.
type ActivityEvent struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Type        string          `json:"type"`
	Category    string          `json:"category"`
	Severity    string          `json:"severity"` // info|success|warning|error|critical
	Title       string          `json:"title"`
	Description *string         `json:"description,omitempty"`
	Actor       *ActivityActor  `json:"actor,omitempty"`
	Target      *ActivityTarget `json:"target,omitempty"`
	At          time.Time       `json:"at"`
	Source      *string         `json:"source,omitempty"`
	IP          *string         `json:"ip,omitempty"`
	Location    *string         `json:"location,omitempty"`
	Device      *string         `json:"device,omitempty"`
	Browser     *string         `json:"browser,omitempty"`
	Status      *string         `json:"status,omitempty"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}

// ActivityActor is the principal that caused the event (user, system, or agent).
type ActivityActor struct {
	ID   *uuid.UUID `json:"id,omitempty"`
	Name string     `json:"name,omitempty"`
	Type string     `json:"type"`
}

// ActivityTarget is the resource the event acted upon.
type ActivityTarget struct {
	Type  string     `json:"type"`
	ID    *uuid.UUID `json:"id,omitempty"`
	Label string     `json:"label,omitempty"`
}

// StreamFilter narrows the live SSE stream to the caller's interests.
// Empty fields mean "no filter on this dimension."
type StreamFilter struct {
	Types    []string // event type exact match (audit action); empty = all
	Severity string   // minimum severity level; empty = all
	Category string   // exact category match; empty = all
}

// ListFilter narrows the history query. SQL-pushable fields are applied at
// the DB level; Severity and Category are post-fetch (they are computed
// values, not stored in audit.events).
type ListFilter struct {
	Types    []string   // filter by exact audit action values; empty = all
	Severity string     // post-fetch: minimum severity
	Category string     // post-fetch: exact category
	ActorID  uuid.UUID  // filter by actor_user_id; uuid.Nil = all
	Subject  *uuid.UUID // identity timeline: actor OR user-resource target; nil = all
	Search   string     // full-text via websearch_to_tsquery
	From     *time.Time // inclusive lower bound on created_at
	To       *time.Time // inclusive upper bound on created_at
}

// categoryOf and severityOf are the authoritative action to (category, severity)
// mappings, used by both the live stream and the history API so callers see a
// consistent view. Category: first matching prefix wins, so order matters.
// Severity: critical > warning > success > info (highest applicable wins).

var categoryPrefixes = []struct {
	prefix   string
	category string
}{
	{"auth.", CategoryAuthentication},
	{"passkey.", CategoryAuthentication},
	{"recovery.", CategoryAuthentication},
	{"saml.", CategoryAuthentication},
	{"social.", CategoryAuthentication},
	{"ldap.", CategoryAuthentication},
	{"oidc.", CategoryAuthentication},
	{"mfa.", CategoryAuthentication},
	{"rbac.", CategoryAuthorization},
	{"abac.", CategoryAuthorization},
	{"rebac.", CategoryAuthorization},
	{"role.", CategoryAuthorization},
	{"policy.", CategoryAuthorization},
	{"authzen.", CategoryAuthorization},
	{"threat.", CategorySecurity},
	{"risk.", CategorySecurity},
	{"anomaly.", CategorySecurity},
	{"bot.", CategorySecurity},
	{"ip_rule.", CategorySecurity},
	{"audit.", CategorySecurity},
	{"user.", CategoryDirectory},
	{"group.", CategoryDirectory},
	{"tenant.", CategoryDirectory},
	{"invite.", CategoryDirectory},
	{"scim.", CategoryDirectory},
	{"domain.", CategoryDirectory},
	{"agent.", CategoryDeveloper},
	{"apikey.", CategoryDeveloper},
	{"api_key.", CategoryDeveloper},
	{"webhook.", CategoryDeveloper},
	{"credentials.", CategoryDeveloper},
	{"secret.", CategoryDeveloper},
	{"auth_hook.", CategoryDeveloper},
	{"vc.", CategoryDeveloper},
	{"system.", CategorySystem},
}

// severityCriticalInfix are substrings that — wherever they appear in the
// action string — indicate a security incident. Checked before suffix rules.
// "reuse" covers both "revoked_for_reuse" (the outbox event) and any future
// "reuse_detected" naming.
var severityCriticalInfix = []string{
	"reuse",
	"breach",
	"attack",
	"malicious",
}

// severityWarningSuffixes are action suffixes that indicate a failed or
// destructive operation.
var severityWarningSuffixes = []string{
	".failed",
	".locked",
	".blocked",
	".denied",
	".rejected",
	".deleted",
	".purged",
	".revoked",
	".rotated",
	".disabled",
	".suspended",
	".canceled",
	".reset",
	".decommissioned",
}

// severitySuccessSuffixes are action suffixes that indicate a positive
// transition.
var severitySuccessSuffixes = []string{
	".created",
	".updated",
	".enabled",
	".activated",
	".verified",
	".accepted",
	".login",
	".refreshed",
	".registered",
	".enrolled",
	".restored",
}

// categoryOf derives the category from the audit action string.
// The first matching prefix wins; unknown actions fall through to "system".
func categoryOf(action string) string {
	for _, rule := range categoryPrefixes {
		if strings.HasPrefix(action, rule.prefix) {
			return rule.category
		}
	}
	return CategorySystem
}

// severityOf derives the severity from the audit action string.
// Critical > warning > success > info (highest applicable wins).
func severityOf(action string) string {
	// All threat.* actions represent detected security events.
	if strings.HasPrefix(action, "threat.") {
		return SeverityCritical
	}
	for _, s := range severityCriticalInfix {
		if strings.Contains(action, s) {
			return SeverityCritical
		}
	}
	for _, s := range severityWarningSuffixes {
		if strings.HasSuffix(action, s) {
			return SeverityWarning
		}
	}
	for _, s := range severitySuccessSuffixes {
		if strings.HasSuffix(action, s) {
			return SeveritySuccess
		}
	}
	return SeverityInfo
}

// titleOf derives a human-readable title from the audit action string.
// "user.created" → "User Created"; "auth.login.failed" → "Auth Login Failed".
func titleOf(action string) string {
	parts := strings.Split(action, ".")
	for i, p := range parts {
		if p == "" {
			continue
		}
		r := []rune(p)
		r[0] = unicode.ToUpper(r[0])
		parts[i] = string(r)
	}
	return strings.Join(parts, " ")
}

// severityMeets reports whether candidate satisfies minimum. When minimum is
// empty, all candidates satisfy it.
//
//	order: info(0) < success(1) < warning(2) < error(3) < critical(4)
func severityMeets(candidate, minimum string) bool {
	if minimum == "" {
		return true
	}
	order := map[string]int{
		SeverityInfo: 0, SeveritySuccess: 1,
		SeverityWarning: 2, SeverityError: 3, SeverityCritical: 4,
	}
	return order[candidate] >= order[minimum]
}

// matchesStreamFilter reports whether ev should be forwarded to an SSE client
// with the given stream filter.
func matchesStreamFilter(ev ActivityEvent, f StreamFilter) bool {
	if len(f.Types) > 0 {
		found := false
		for _, t := range f.Types {
			if ev.Type == t || strings.HasPrefix(ev.Type, t+".") {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Category != "" && ev.Category != f.Category {
		return false
	}
	return severityMeets(ev.Severity, f.Severity)
}

// matchesListFilter reports whether ev passes the post-fetch list filters
// (severity and category, which are computed and not stored in the DB).
func matchesListFilter(ev ActivityEvent, f ListFilter) bool {
	if f.Category != "" && ev.Category != f.Category {
		return false
	}
	return severityMeets(ev.Severity, f.Severity)
}

// auditRow is the local scan target for the history/replay queries. Columns
// must match the SELECT list in replayHistory and listHistory exactly.
type auditRow struct {
	ID           uuid.UUID
	ActorUserID  *uuid.UUID
	ActorType    string
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           *string
	UserAgent    *string
	CreatedAt    time.Time
	Metadata     []byte
	TenantID     uuid.UUID // scanned last; used to populate ActivityEvent.TenantID
}

// mapAuditRow converts one DB row from audit.events into a public ActivityEvent.
func mapAuditRow(r auditRow) ActivityEvent {
	ev := ActivityEvent{
		ID:       r.ID,
		TenantID: r.TenantID,
		Type:     r.Action,
		Category: categoryOf(r.Action),
		Severity: severityOf(r.Action),
		Title:    titleOf(r.Action),
		At:       r.CreatedAt.UTC(),
		IP:       r.IP,
	}

	if r.ActorUserID != nil || r.ActorType != "" {
		t := r.ActorType
		if t == "" {
			t = "user"
		}
		ev.Actor = &ActivityActor{ID: r.ActorUserID, Type: t}
	}

	if r.ResourceType != "" {
		ev.Target = &ActivityTarget{
			Type: r.ResourceType,
			ID:   r.ResourceID,
		}
	}

	if len(r.Metadata) > 0 && string(r.Metadata) != "null" && string(r.Metadata) != "{}" {
		var meta map[string]any
		if err := json.Unmarshal(r.Metadata, &meta); err == nil && len(meta) > 0 {
			ev.Metadata = meta
		}
	}

	if r.UserAgent != nil && *r.UserAgent != "" {
		ua := parseBrowser(*r.UserAgent)
		if ua != "" {
			ev.Browser = &ua
		}
	}

	return ev
}

// parseBrowser extracts a coarse browser label from a user-agent string.
func parseBrowser(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Chromium"):
		return "Chrome"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome"):
		return "Safari"
	case strings.Contains(ua, "curl"):
		return "curl"
	default:
		return ""
	}
}

// outboxPayload is a best-effort extraction struct for the common fields
// embedded in domain event JSON payloads. All domain events include tenant_id;
// actor and resource fields vary by domain and are extracted opportunistically.
type outboxPayload struct {
	TenantID    *uuid.UUID `json:"tenant_id"`
	ID          *uuid.UUID `json:"id"`
	UserID      *uuid.UUID `json:"user_id"`       // auth.session.* events
	ActorUserID *uuid.UUID `json:"actor_user_id"` // future-proofing
	IP          string     `json:"ip"`
}

// mapOutboxEvent converts a raw NATS outbox message into an ActivityEvent.
// eventType comes from the Qeet-Event-Type header; tenantID was already
// extracted by the hub dispatcher. The full payload is attached as metadata.
func mapOutboxEvent(subject, eventType string, tenantID uuid.UUID, payload []byte) ActivityEvent {
	var raw outboxPayload
	_ = json.Unmarshal(payload, &raw)

	ev := ActivityEvent{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     eventType,
		Category: categoryOf(eventType),
		Severity: severityOf(eventType),
		Title:    titleOf(eventType),
		At:       time.Now().UTC(),
	}

	// Actor: prefer actor_user_id, fall back to user_id (auth events).
	actorID := raw.ActorUserID
	if actorID == nil {
		actorID = raw.UserID
	}
	if actorID != nil {
		ev.Actor = &ActivityActor{ID: actorID, Type: "user"}
	}

	// Target: the payload's id field is the primary resource identifier.
	if raw.ID != nil {
		ev.Target = &ActivityTarget{
			Type: resourceTypeFrom(eventType),
			ID:   raw.ID,
		}
	}

	if raw.IP != "" {
		ev.IP = &raw.IP
	}

	// Attach the full payload as opaque metadata so UI can surface domain fields.
	var meta map[string]any
	if err := json.Unmarshal(payload, &meta); err == nil {
		delete(meta, "tenant_id") // redundant — already in the envelope
		if len(meta) > 0 {
			ev.Metadata = meta
		}
	}

	return ev
}

// resourceTypeFrom extracts the coarse resource type from an event type.
// "user.created" → "user", "group.member_added" → "group".
func resourceTypeFrom(eventType string) string {
	if idx := strings.Index(eventType, "."); idx > 0 {
		return eventType[:idx]
	}
	return eventType
}
