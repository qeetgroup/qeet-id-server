package activity

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// activityRow is one of the activity queries' rows, which share their columns.
type activityRow interface {
	dbgen.ListActivityHistoryRow | dbgen.ReplayActivityHistoryRow | dbgen.GetActivityEventByIDRow |
		dbgen.ListRelatedByRequestIDRow | dbgen.ListRelatedByActorRow
}

// toAuditRow converts an activity query's row into the auditRow mapAuditRow
// reads.
func toAuditRow[R activityRow](row R) auditRow {
	r := dbgen.ListActivityHistoryRow(row)
	out := auditRow{
		ID:             r.ID,
		ActorType:      r.ActorType,
		Action:         r.Action,
		ResourceType:   r.ResourceType,
		UserAgent:      r.UserAgent,
		RequestID:      r.RequestID,
		ActorName:      firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:      r.CreatedAt,
		Metadata:       r.Metadata,
		OrganizationID: postgres.ZeroIfNull(r.OrganizationID),
	}
	out.ActorUserID = r.ActorUserID
	out.ResourceID = r.ResourceID
	if r.Ip != "" {
		out.IP = &r.Ip
	}
	return out
}

// auditRow is the common shape of the activity query rows, which mapAuditRow
// turns into an ActivityEvent.
type auditRow struct {
	ID             uuid.UUID
	ActorUserID    *uuid.UUID
	ActorType      string
	Action         string
	ResourceType   string
	ResourceID     *uuid.UUID
	IP             *string
	UserAgent      *string
	RequestID      *string
	ActorName      *string
	CreatedAt      time.Time
	Metadata       []byte
	OrganizationID uuid.UUID
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
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Type:           r.Action,
		Category:       categoryOf(r.Action),
		Severity:       severityOf(r.Action),
		Title:          titleOf(r.Action),
		At:             r.CreatedAt.UTC(),
		IP:             r.IP,
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
	d := httpx.Parse(ua)
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
	return strutil.NilIfEmpty(d.Browser), strutil.NilIfEmpty(d.Platform), strutil.NilIfEmpty(d.Kind)
}

// placeOf is the country and city an event's metadata records the request
// came from (its "geo"), and the two as a place ("Pune, IN"); each nil when
// unknown.
func placeOf(meta map[string]any) (country, city, location *string) {
	geo, _ := meta["geo"].(map[string]any)
	c, _ := geo["country"].(string)
	t, _ := geo["city"].(string)
	country, city = strutil.NilIfEmpty(c), strutil.NilIfEmpty(t)
	switch {
	case c != "" && t != "":
		location = strutil.NilIfEmpty(t + ", " + c)
	case c != "":
		location = country
	}
	return country, city, location
}
