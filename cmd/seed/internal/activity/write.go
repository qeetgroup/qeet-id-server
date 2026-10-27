package activity

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

// write stores the history with COPY, as the database user: tens of
// thousands of rows the API wrote one at a time as they happened.
func (h *history) write() {
	h.sortSessions()
	sessions := make([][]any, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, []any{
			s.id, s.p.ID, s.org.ID, addr(s.dev.IP), s.dev.UserAgent, us(s.created), us(s.lastSeen), optTime(s.ended),
			optID(s.superseded), us(s.expires), s.idle, optString(s.dev.Country), optString(s.factor), us(s.signedIn()),
		})
	}
	h.copy("sessions", pgx.Identifier{"auth", "sessions"}, []string{"id", "user_id", "tenant_id", "ip", "user_agent",
		"created_at", "last_seen_at", "revoked_at", "superseded_by", "expires_at", "idle_timeout", "country", "second_factor",
		"signed_in_at"}, sessions)

	events := make([][]any, 0, len(h.events))
	for _, ev := range h.events {
		e := ev.e
		if e.ActorType == "" {
			e.ActorType = "user"
		}
		meta, err := json.Marshal(e.Metadata)
		world.Must(err, "encode audit metadata")
		if string(meta) == "null" {
			meta = []byte("{}")
		}
		at := us(ev.at)
		events = append(events, []any{uuid.New(), e.TenantID, e.ActorUserID, e.ActorType, e.Action, e.ResourceType, e.ResourceID,
			addr(e.IP), optString(e.UserAgent), optString(e.RequestID), meta, at, at})
	}
	h.copy("audit history", pgx.Identifier{"audit", "events"}, []string{"id", "tenant_id", "actor_user_id", "actor_type", "action",
		"resource_type", "resource_id", "ip", "user_agent", "request_id", "metadata", "created_at", "scored_at"}, events)

	contexts := make([][]any, 0, len(h.contexts))
	for _, c := range h.contexts {
		contexts = append(contexts, []any{uuid.New(), c.tenant, c.user, c.deviceKey, optString(c.country), us(c.seen)})
	}
	h.copy("sign-in context", pgx.Identifier{"auth", "login_context_history"},
		[]string{"id", "tenant_id", "user_id", "device_key", "country", "seen_at"}, contexts)

	mails := make([][]any, 0, len(h.mails))
	for _, m := range h.mails {
		mails = append(mails, []any{m.id, m.tenant, delivery.HashAddress(m.to), delivery.Hint(m.to), m.template, "ses",
			optString(m.providerID), m.status, m.reason, us(m.sent), us(m.updated)})
	}
	h.copy("email deliveries", pgx.Identifier{"platform", "email_messages"}, []string{"id", "tenant_id", "to_hash", "to_hint",
		"template", "provider", "provider_message_id", "status", "status_reason", "sent_at", "updated_at"}, mails)
}

// writeSuppressions stores the suppression list after the messages that
// caused it.
func (h *history) writeSuppressions(sups []suppression) {
	rows := make([][]any, 0, len(sups))
	for _, s := range sups {
		var by *uuid.UUID
		if s.clearedBy != nil {
			by = ptr(s.clearedBy.ID)
		}
		rows = append(rows, []any{s.id, s.tenant, delivery.HashAddress(s.address), delivery.Hint(s.address), s.reason, s.detail,
			s.message, us(s.created), optTime(s.cleared), by})
	}
	h.copy("email suppressions", pgx.Identifier{"platform", "email_suppressions"}, []string{"id", "tenant_id", "address_hash",
		"address_hint", "reason", "detail", "message_id", "created_at", "cleared_at", "cleared_by"}, rows)
}

func (h *history) copy(what string, table pgx.Identifier, columns []string, rows [][]any) {
	if len(rows) == 0 {
		return
	}
	_, err := h.w.Admin.CopyFrom(h.w.Ctx, table, columns, pgx.CopyFromRows(rows))
	world.Must(err, "write "+what)
}

// us is t at the database's precision.
func us(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return ptr(us(t))
}

func optID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// addr is an address for an inet column, or nil.
func addr(ip string) any {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return a
}
