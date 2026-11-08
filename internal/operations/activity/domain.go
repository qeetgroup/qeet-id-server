// Package activity serves the Live Activity feed: a tenant-filtered SSE stream
// of live events from the NATS outbox, and paginated history from audit.events.
// Both sources map to ActivityEvent, so live and history look the same.
package activity

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/useragent"
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
	Country     *string         `json:"country,omitempty"`
	City        *string         `json:"city,omitempty"`
	Device      *string         `json:"device,omitempty"`
	OS          *string         `json:"os,omitempty"`
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

// ListFilter narrows the history query. Severities and Categories are those
// activity derives from the action, matched in the query by
// audit.activity_severity and audit.activity_category.
type ListFilter struct {
	Types         []string    // filter by exact audit action values; empty = all
	Severities    []string    // any of these severities; empty = all
	MinSeverity   string      // at least this severity; "" = all
	Categories    []string    // any of these categories; empty = all
	ActorID       uuid.UUID   // filter by actor_user_id; uuid.Nil = all
	Subject       *uuid.UUID  // identity timeline: actor OR user-resource target; nil = all
	Search        string      // words, as prefixes, or the actor's name or email (audit.search_query)
	From          *time.Time  // inclusive lower bound on created_at
	To            *time.Time  // inclusive upper bound on created_at
	ResourceTypes []string    // any of these resource types; empty = all
	ResourceID    *uuid.UUID  // the resource acted on; nil = all
	IP            *netip.Addr // the requester's address; nil = all
}

// categoryPrefixes maps an action prefix to its category. The first match wins,
// so order matters. Every recorded action's prefix is listed, the system ones
// too, so none is filed under system for want of an entry.
var categoryPrefixes = []struct {
	prefix   string
	category string
}{
	{"auth.", CategoryAuthentication},
	{"auth_policy.", CategoryAuthentication},
	{"passkey.", CategoryAuthentication},
	{"recovery.", CategoryAuthentication},
	{"saml.", CategoryAuthentication},
	{"social.", CategoryAuthentication},
	{"social_provider.", CategoryAuthentication},
	{"ldap.", CategoryAuthentication},
	{"oidc_connection.", CategoryAuthentication},
	{"oidc.", CategoryAuthentication},
	{"oauth.", CategoryAuthentication},
	{"mfa.", CategoryAuthentication},
	{"session.", CategoryAuthentication},
	{"admin_portal.", CategoryAuthentication},
	{"rbac.", CategoryAuthorization},
	{"abac.", CategoryAuthorization},
	{"abac_policy.", CategoryAuthorization},
	{"rebac.", CategoryAuthorization},
	{"role.", CategoryAuthorization},
	{"access_request.", CategoryAuthorization},
	{"policy.", CategoryAuthorization},
	{"authzen.", CategoryAuthorization},
	{"threat.", CategorySecurity},
	{"risk.", CategorySecurity},
	{"anomaly.", CategorySecurity},
	{"bot.", CategorySecurity},
	{"ip_rules.", CategorySecurity},
	{"rate_limits.", CategorySecurity},
	{"security_policy.", CategorySecurity},
	{"audit.", CategorySecurity},
	{"siem.", CategorySecurity},
	{"retention.", CategorySecurity},
	{"compliance.", CategorySecurity},
	{"gdpr.", CategorySecurity},
	{"user.", CategoryDirectory},
	{"group.", CategoryDirectory},
	{"group_template.", CategoryDirectory},
	{"tenant.", CategoryDirectory},
	{"invite.", CategoryDirectory},
	{"scim.", CategoryDirectory},
	{"directory.", CategoryDirectory},
	{"domain.", CategoryDirectory},
	{"branding.", CategoryDirectory},
	{"email.", CategoryDirectory},
	{"email_template.", CategoryDirectory},
	{"phone.", CategoryDirectory},
	{"agent.", CategoryDeveloper},
	{"apikey.", CategoryDeveloper},
	{"api_key.", CategoryDeveloper},
	{"service_principal.", CategoryDeveloper},
	{"webhook.", CategoryDeveloper},
	{"credential.", CategoryDeveloper},
	{"secret.", CategoryDeveloper},
	{"vault.", CategoryDeveloper},
	{"auth_hook.", CategoryDeveloper},
	{"vc.", CategoryDeveloper},
	{"qeetai.", CategoryDeveloper},
	{"billing.", CategorySystem},
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

// severityErrorWords mark a failure or denial, which the console shows as
// "Failed".
var severityErrorWords = []string{"failed", "locked", "blocked", "throttled", "denied", "rejected", "refused"}

// severityWarningWords mark destructive but expected operations, which the
// console shows as "Warning".
var severityWarningWords = []string{
	"deleted", "purged", "revoked", "rotated", "disabled", "suspended", "canceled", "reset", "decommissioned",
}

// severitySuccessWords mark a positive transition.
var severitySuccessWords = []string{
	"created", "updated", "enabled", "activated", "verified", "accepted", "confirmed", "login", "succeeded",
	"refreshed", "registered", "enrolled", "restored",
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
// critical substrings come first, then the error, warning and success words,
// in that order, matched against every word of the action, split at "." and
// "_": "auth.sign_in_failed" is an error. Anything else is info.
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
	words := strings.FieldsFunc(action, func(r rune) bool { return r == '.' || r == '_' })
	hasWord := func(set []string) bool {
		return slices.ContainsFunc(words, func(w string) bool { return slices.Contains(set, w) })
	}
	switch {
	case hasWord(severityErrorWords):
		return SeverityError
	case hasWord(severityWarningWords):
		return SeverityWarning
	case hasWord(severitySuccessWords):
		return SeveritySuccess
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
		ev.Browser, ev.OS, ev.Device = describeAgent(*r.UserAgent)
	}
	ev.Country, ev.City, ev.Location = placeOf(ev.Metadata)

	// request_id may be NULL or empty; surface it only when set.
	if r.RequestID != nil && *r.RequestID != "" {
		rid := *r.RequestID
		ev.RequestID = &rid
	}

	return ev
}

// describeAgent is the browser, operating system and device type ("desktop",
// "mobile" or "tablet") a user agent names; each nil when it doesn't say.
func describeAgent(ua string) (browser, os, device *string) {
	d := useragent.Parse(ua)
	if d.Browser == "" && strings.Contains(ua, "curl") {
		d.Browser = "curl"
	}
	switch d.Platform {
	case "iPhone":
		d.Platform = "iOS"
	case "iPad":
		d.Platform = "iPadOS"
	}
	if d.Kind == "unknown" {
		d.Kind = ""
	}
	return nonEmpty(d.Browser), nonEmpty(d.Platform), nonEmpty(d.Kind)
}

// placeOf is the country and city an event's metadata records the request
// came from (its "geo"), and the two as a place ("Pune, IN"); each nil when
// unknown.
func placeOf(meta map[string]any) (country, city, location *string) {
	geo, _ := meta["geo"].(map[string]any)
	c, _ := geo["country"].(string)
	t, _ := geo["city"].(string)
	country, city = nonEmpty(c), nonEmpty(t)
	switch {
	case c != "" && t != "":
		location = nonEmpty(t + ", " + c)
	case c != "":
		location = country
	}
	return country, city, location
}

// nonEmpty is &s, or nil for "".
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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
