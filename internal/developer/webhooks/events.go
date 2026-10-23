package webhook

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// EventType is an event a webhook subscription can name.
type EventType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Events is the event catalogue: every event a subscription can receive. An
// event's name is its version, so a payload that changes incompatibly gets a
// new name; adding a field to one does not.
var Events = []EventType{
	{"user.created", "A person was added to the organisation, by an administrator or over SCIM."},
	{"user.updated", "SCIM changed a person's profile or status."},
	{"user.suspended", "A person's account was suspended."},
	{"user.reactivated", "A suspended account was reactivated."},
	{"user.deleted", "A person was deleted from the organisation."},
	{"user.password_set", "An administrator set a person's password, ending their sessions."},
	{"user.bulk_imported", "A bulk import of people finished, with how many rows succeeded and failed."},
	{"auth.password_changed", "A person changed their own password."},
	{"session.revoked", "A session ended, with the reason; its tokens stop working."},
	{"token.claims_change", "A person's roles changed, so their next access token carries different claims."},
	{"group.created", "A group was created."},
	{"group.updated", "A group was changed."},
	{"group.deleted", "A group was deleted."},
	{"group.member_added", "A person was added to a group."},
	{"group.member_removed", "A person was removed from a group."},
	{"group_template.applied", "A group template was applied, creating its groups."},
	{"domain.created", "A domain was added for verification."},
	{"domain.verified", "A domain was verified."},
	{"domain.deleted", "A domain was removed."},
	{"agent.created", "An AI agent was registered."},
	{"agent.suspended", "An AI agent was suspended; its tokens stop working."},
	{"agent.resumed", "A suspended AI agent was made active again."},
	{"agent.decommissioned", "An AI agent was decommissioned for good."},
	{"agent.deleted", "An AI agent was deleted."},
	{"agent.sponsor_transferred", "A person's AI agents were given to another sponsor."},
	{"agent.kill_switch", "Every active AI agent of the organisation was suspended at once."},
	{"rebac.tuple_written", "A relationship was written."},
	{"rebac.tuple_deleted", "A relationship was deleted."},
	{"abac_policy.created", "An attribute-based access policy was created."},
	{"abac_policy.updated", "An attribute-based access policy was changed."},
	{"abac_policy.deleted", "An attribute-based access policy was deleted."},
	{"auth_hook.created", "An authentication hook was created."},
	{"auth_hook.updated", "An authentication hook was enabled, disabled or changed."},
	{"auth_hook.deleted", "An authentication hook was deleted."},
	{"siem.sink_created", "A log stream to a SIEM was created."},
	{"siem.sink_updated", "A log stream to a SIEM was enabled or disabled."},
	{"siem.sink_deleted", "A log stream to a SIEM was deleted."},
	{"rate_limits.updated", "The organisation's rate limits were changed."},
	{"rate_limits.deleted", "The organisation's rate limits were reset to the defaults."},
	{"credential.issued", "A verifiable credential was issued."},
	{"credential.revoked", "A verifiable credential was revoked."},
	{"oidc.client_locked_out", "An application was locked out after too many wrong secrets."},
	{"tenant.suspended", "The organisation was suspended, ending its sessions."},
	{"tenant.reactivated", "The organisation was reactivated."},
	{"tenant.deleted", "The organisation was deleted, ending its sessions."},
}

// TestEvent is the event the test call sends. No subscription names it.
const TestEvent = "test.ping"

// knownEvent reports whether name is in the catalogue.
func knownEvent(name string) bool {
	return slices.ContainsFunc(Events, func(e EventType) bool { return e.Name == name })
}

// subscribableEvents returns the events a subscription names, once each, or
// an error when it names none or one outside the catalogue.
func subscribableEvents(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, errs.ErrWebhookEventsRequired
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !knownEvent(name) {
			return nil, errs.ErrWebhookEventUnknown.WithDetail(name)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// Event is the body of every delivery. ID is the same in every delivery of
// one event, retries included, so a receiver deduplicates on it.
type Event struct {
	ID         uuid.UUID       `json:"id"`
	Type       string          `json:"type"`
	TenantID   uuid.UUID       `json:"tenant_id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Data       json.RawMessage `json:"data"`
}

// queue inserts a delivery of e for each of its organisation's active
// subscriptions that name it. Queuing an event already queued is a no-op.
func (s *Service) queue(ctx context.Context, q *dbgen.Queries, e Event) error {
	ids, err := q.GetSubscriptionsForEvent(ctx, dbgen.GetSubscriptionsForEventParams{TenantID: e.TenantID, EventType: e.Type})
	if err != nil || len(ids) == 0 {
		return err
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := q.InsertDelivery(ctx, dbgen.InsertDeliveryParams{
			SubscriptionID: id, EventID: e.ID, EventType: e.Type, Payload: body,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Relay returns a Publisher that queues each committed outbox event in the
// catalogue for its organisation's subscriptions, then hands it to next. The
// outbox retries an event next failed; queuing it again is a no-op.
func (s *Service) Relay(next outbox.Publisher) outbox.Publisher {
	return relay{s: s, next: next}
}

type relay struct {
	s    *Service
	next outbox.Publisher
}

func (r relay) Publish(ctx context.Context, m outbox.Message) error {
	if knownEvent(m.EventType) {
		// An event belongs to the organisation its payload names; one that
		// names none, such as a person's with no organisation, has no subscribers.
		var owner struct {
			TenantID uuid.UUID `json:"tenant_id"`
		}
		if json.Unmarshal(m.Payload, &owner) == nil && owner.TenantID != uuid.Nil {
			e := Event{ID: m.ID, Type: m.EventType, TenantID: owner.TenantID, OccurredAt: m.OccurredAt.UTC(), Data: m.Payload}
			if err := r.s.queue(ctx, r.s.q, e); err != nil {
				return err
			}
		}
	}
	return r.next.Publish(ctx, m)
}
