// Package activity serves the Live Activity feed: a tenant-filtered SSE stream
// of live events from the NATS outbox, and paginated history from audit.events.
// Both sources map to ActivityEvent, so live and history look the same.
package activity

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Severity levels of an ActivityEvent, lowest first. They match the console's
// ActivityEvent severity values.
const (
	SeverityInfo     = "info"
	SeveritySuccess  = "success"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// Categories group event types into the coarse domains the console filters by.
const (
	CategoryAuthentication = "authentication"
	CategoryAuthorization  = "authorization"
	CategorySecurity       = "security"
	CategoryDirectory      = "directory"
	CategoryDeveloper      = "developer"
	CategorySystem         = "system"
)

// ActivityEvent is the wire form of a domain event, from either the live NATS
// stream or the audit log. The SSE handler drops any event whose TenantID is not
// the connection's tenant, in case the hub ever mis-routes one.
type ActivityEvent struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Type        string          `json:"type"`
	Category    string          `json:"category"`
	Severity    string          `json:"severity"`
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
	RequestID   *string         `json:"request_id,omitempty"`
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

// ListFilter narrows the history query. Severity and Category are applied after
// the fetch, because they are derived from the action rather than stored.
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

// categoryPrefixes maps an action prefix to its category. The first match wins,
// so order matters.
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

// severityCriticalInfix lists substrings that mark an action as a security
// incident wherever they appear, such as "reuse" in
// "auth.session.revoked_for_reuse".
var severityCriticalInfix = []string{
	"reuse",
	"breach",
	"attack",
	"malicious",
}

// severityErrorSuffixes are action suffixes for a failure or denial, which the
// console shows as "Failed".
var severityErrorSuffixes = []string{
	".failed",
	".locked",
	".blocked",
	".denied",
	".rejected",
}

// severityWarningSuffixes are action suffixes for destructive but expected
// operations, which the console shows as "Warning".
var severityWarningSuffixes = []string{
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

// categoryOf returns the category of an audit action: the first matching entry
// in categoryPrefixes, or CategorySystem.
func categoryOf(action string) string {
	for _, rule := range categoryPrefixes {
		if strings.HasPrefix(action, rule.prefix) {
			return rule.category
		}
	}
	return CategorySystem
}

// severityOf returns the severity of an audit action. threat.* actions and
// critical substrings come first, then the error, warning and success suffixes,
// in that order; anything else is info.
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
	for _, s := range severityErrorSuffixes {
		if strings.HasSuffix(action, s) {
			return SeverityError
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

// outcomeOf maps a severity to the outcome bucket of the console's summary:
// error and critical become "failed"; success, warning and info are unchanged.
func outcomeOf(sev string) string {
	switch sev {
	case SeveritySuccess:
		return "success"
	case SeverityWarning:
		return "warning"
	case SeverityError, SeverityCritical:
		return "failed"
	default:
		return "info"
	}
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

// severityMeets reports whether candidate is at least minimum, in the order
// info < success < warning < error < critical. An empty minimum matches all.
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

// auditRow is the common shape of the activity query rows, which mapAuditRow
// turns into an ActivityEvent.
type auditRow struct {
	ID           uuid.UUID
	ActorUserID  *uuid.UUID
	ActorType    string
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           *string
	UserAgent    *string
	RequestID    *string
	ActorName    *string
	CreatedAt    time.Time
	Metadata     []byte
	TenantID     uuid.UUID
}

// firstNonEmpty returns the first non-nil, non-empty value, or nil.
func firstNonEmpty(vals ...*string) *string {
	for _, v := range vals {
		if v != nil && *v != "" {
			return v
		}
	}
	return nil
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
		actor := &ActivityActor{ID: r.ActorUserID, Type: t}
		if r.ActorName != nil {
			actor.Name = *r.ActorName
		}
		ev.Actor = actor
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

	// request_id may be NULL or empty; surface it only when set.
	if r.RequestID != nil && *r.RequestID != "" {
		rid := *r.RequestID
		ev.RequestID = &rid
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

// outboxPayload holds the common fields of a domain event payload. Every event
// carries tenant_id; the other fields are present only for some domains.
type outboxPayload struct {
	TenantID    *uuid.UUID `json:"tenant_id"`
	ID          *uuid.UUID `json:"id"`
	UserID      *uuid.UUID `json:"user_id"`
	ActorUserID *uuid.UUID `json:"actor_user_id"`
	IP          string     `json:"ip"`
}

// mapOutboxEvent converts a NATS outbox message into an ActivityEvent, with the
// whole payload as metadata. eventType comes from the Qeet-Event-Type header.
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
