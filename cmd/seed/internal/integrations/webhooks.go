package integrations

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// window is how far back webhook delivery history goes.
const window = 14 * 24 * time.Hour

// subSpec is a webhook subscription: its consumer, the events it takes, and
// its state today — active, failing (for hours), disabled by an administrator
// or auto-disabled by its failures (days ago).
type subSpec struct {
	url     string
	events  []string
	by      []who
	created float64
	state   string
	since   float64
	// fails is how its deliveries fail while it fails: 5xx, timeout or dns.
	fails string
	// ok is the body its endpoint answers a delivery with, and okStatus the
	// status.
	ok       string
	okStatus int
	rotated  float64 // hours ago its signing secret was rotated; 0 never
	tested   float64 // hours ago someone sent it a test event; 0 never
}

var (
	userEvents  = []string{"user.created", "user.updated", "user.suspended", "user.reactivated", "user.deleted"}
	groupEvents = []string{"group.created", "group.updated", "group.deleted", "group.member_added", "group.member_removed"}
	alertEvents = []string{"user.suspended", "user.deleted", "user.password_set", "auth.password_changed", "session.revoked",
		"oidc.client_locked_out", "agent.suspended", "agent.kill_switch", "agent.decommissioned", "auth_hook.updated",
		"auth_hook.deleted", "siem.sink_updated", "siem.sink_deleted", "abac_policy.updated", "abac_policy.deleted",
		"rate_limits.updated", "credential.revoked", "tenant.suspended"}
)

// subSpecs are each organisation's webhook subscriptions, on its own hosts,
// none of which resolve.
var subSpecs = map[string][]subSpec{
	"qeet": {
		{url: "https://hooks.qeet.in/people/qeet-id-events", events: append(append([]string{}, userEvents...), groupEvents...),
			by: []who{email("aarav@qeet.in")}, created: 280, state: "active", ok: `{"received":true}`, okStatus: 202, rotated: 6, tested: 5.9},
		{url: "https://notify.qeet.in/v1/sources/qeet-id/webhooks", events: []string{"user.created", "user.password_set", "auth.password_changed", "session.revoked", "agent.suspended"},
			by: []who{email("rohan@qeet.in")}, created: 116, state: "active", ok: `{"status":"queued"}`, okStatus: 200},
		{url: "https://alerts.qeet.in/slack/identity-alerts", events: alertEvents,
			by: []who{both(team("Site Reliability"), builders)}, created: 240, state: "failing", since: 30, fails: "5xx", ok: "ok", okStatus: 200, tested: 1.6},
		{url: "https://warehouse.qeet.in/ingest/qeet-id/webhooks", events: []string{"user.created", "user.deleted", "session.revoked", "auth.password_changed", "group.member_added"},
			by: []who{email("rohan@qeet.in")}, created: 200, state: "disabled", since: 9, ok: "", okStatus: 204},
		{url: "https://staging-api.qeet.in/notify/v1/webhooks/qeet-id", events: []string{"user.created", "user.password_set", "auth.password_changed", "session.revoked"},
			by: []who{email("rohan@qeet.in")}, created: 120, state: "auto", since: 5.2, fails: "dns", ok: `{"status":"queued"}`, okStatus: 200},
	},
	"northwind": {
		{url: "https://siem-relay.northwindcapital.in/qeet-id/events", events: []string{"user.suspended", "user.deleted", "user.password_set", "session.revoked",
			"oidc.client_locked_out", "agent.suspended", "agent.kill_switch", "abac_policy.updated", "abac_policy.deleted", "rate_limits.updated"},
			by: []who{both(dept("Information Security"), builders)}, created: 300, state: "active", ok: "", okStatus: 204},
		{url: "https://itsm-bridge.northwindcapital.in/servicenow/qeet-id", events: append(append([]string{}, userEvents...), "group.member_added", "group.member_removed"),
			by: []who{both(team("IT Operations"), builders), both(dept("Technology"), builders)}, created: 240, state: "failing", since: 28, fails: "5xx",
			ok: `{"result":{"status":"inserted"}}`, okStatus: 201, tested: 0.7},
		{url: "https://los-hooks.northwindcapital.in/legacy/qeet", events: []string{"user.created", "user.deleted"},
			by: []who{both(team("Platform Engineering"), builders)}, created: 330, state: "disabled", since: 60, ok: "OK", okStatus: 200},
	},
	"meridian": {
		{url: "https://epic-bridge.meridianhealth.us/qeet-id/webhooks", events: userEvents,
			by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 235, state: "active", ok: `{"status":"accepted"}`, okStatus: 202},
		{url: "https://teams-relay.meridianhealth.us/identity-alerts", events: alertEvents,
			by: []who{both(dept("Security"), builders)}, created: 190, state: "active", ok: "1", okStatus: 200},
		{url: "https://dw-ingest.meridianhealth.us/qeet-id/events", events: append(append([]string{}, userEvents...), "group.member_added", "group.member_removed", "session.revoked"),
			by: []who{both(dept("Security"), builders)}, created: 170, state: "auto", since: 2.1, fails: "5xx", ok: "", okStatus: 204},
	},
	"lumen": {
		{url: "https://api.lumenlabshq.dev/internal/webhooks/qeet-id", events: []string{"user.created", "user.deleted", "session.revoked", "token.claims_change", "group.member_added", "group.member_removed"},
			by: []who{both(team("Core Platform"), builders)}, created: 225, state: "active", ok: `{"ok":true}`, okStatus: 200, rotated: 400},
		{url: "https://hooks.lumenlabshq.dev/slack/identity-alerts", events: []string{"agent.suspended", "agent.kill_switch", "abac_policy.updated",
			"auth_hook.updated", "credential.revoked", "oidc.client_locked_out", "rate_limits.updated"},
			by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 110, state: "active", ok: "ok", okStatus: 200},
		{url: "https://events.lumenlabshq.dev/segment/forward", events: []string{"user.created", "user.deleted", "session.revoked"},
			by: []who{both(team("Core Platform"), builders)}, created: 180, state: "disabled", since: 9.5, ok: `{"success":true}`, okStatus: 200},
	},
	"aster": {
		{url: "https://ops.asterretail.in/hooks/qeet-id/staff-roster", events: []string{"user.created", "user.suspended", "user.deleted", "group.member_added", "group.member_removed"},
			by: []who{email("lucia.garcia@lumenlabshq.dev")}, created: 150, state: "active", ok: `{"synced":true}`, okStatus: 200},
	},
}

// sub is a seeded subscription and the stretch of time it received events.
type sub struct {
	spec        subSpec
	id          uuid.UUID
	from, until time.Time // receiving events; until is now unless disabled
	failing     time.Time // zero unless failing
}

// refuseUnknownEvent checks the webhook service still refuses a subscription
// to an event outside its catalogue, as the console's form relies on.
func (d *dev) refuseUnknownEvent() {
	w := d.w
	for _, o := range w.Orgs {
		if !o.Has("starter") {
			continue
		}
		tx, err := w.Pool.Begin(w.Ctx)
		w.Check(err, "begin")
		_, err = w.Deps.Webhook.Service.Create(w.Ctx, tx, webhook.CreateInput{TenantID: o.ID,
			URL: "https://hooks." + o.Spec.Domain + "/qeet-id", Events: []string{"user.login"}})
		_ = tx.Rollback(w.Ctx)
		if !errors.Is(err, errs.ErrWebhookEventUnknown) {
			w.Check(fmt.Errorf("a subscription to user.login was not refused: %w", err), "unknown webhook event")
		}
		return
	}
}

// subscriptions creates the organisation's webhook subscriptions through the
// webhook service, audited as the console does, then brings each to its state.
func (d *dev) subscriptions(o *world.Org) {
	w := d.w
	if !o.Spec.Features.Webhooks || !o.Has("starter") {
		return
	}
	if d.subs == nil {
		d.subs = map[uuid.UUID][]sub{}
	}
	for _, s := range subSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		var created *webhook.Subscription
		w.At(at, func() {
			w.Tx("webhook "+s.url, func(tx pgx.Tx) error {
				var err error
				created, err = w.Deps.Webhook.Service.Create(w.Ctx, tx, webhook.CreateInput{TenantID: o.ID, URL: s.url, Events: s.events})
				if err != nil {
					return err
				}
				return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, "webhook.subscription_created", "webhook_subscription", created.ID,
					map[string]any{"url": created.URL, "events": created.Events}))
			})
		})
		sb := sub{spec: s, id: created.ID, from: at, until: w.Now}
		if s.rotated > 0 && w.Now.Add(-time.Duration(s.rotated)*time.Hour).After(at) {
			rt := w.Now.Add(-time.Duration(s.rotated) * time.Hour)
			rotator := person(o, rt, email(by.Email), builders)
			w.At(rt, func() {
				w.Tx("rotate webhook secret", func(tx pgx.Tx) error {
					_, _, err := w.Deps.Webhook.Service.RotateSecret(w.Ctx, tx, created.ID, o.ID)
					if err != nil {
						return err
					}
					return audit.Record(w.Ctx, tx, d.as(rotator).Event(o.ID, "webhook.secret_rotated", "webhook_subscription", created.ID,
						map[string]any{"previous_secret_expires_at": rt.Add(webhook.SecretRotationOverlap)}))
				})
			})
			w.Exec("webhook secret overlap", `UPDATE tenant.webhook_subscriptions SET previous_secret_expires_at = $3 WHERE id = $1 AND tenant_id = $2`,
				created.ID, o.ID, rt.Add(webhook.SecretRotationOverlap))
		}
		switch s.state {
		case "failing":
			sb.failing = w.Now.Add(-time.Duration(s.since * float64(time.Hour)))
			w.Exec("webhook failing", `UPDATE tenant.webhook_subscriptions SET failing_since = $3 WHERE id = $1 AND tenant_id = $2`, created.ID, o.ID, sb.failing)
		case "disabled":
			dt := d.when(o, s.since, by)
			sb.until = dt
			w.At(dt, func() {
				w.Tx("disable webhook", func(tx pgx.Tx) error {
					_, u, err := w.Deps.Webhook.Service.Disable(w.Ctx, tx, created.ID, o.ID, d.as(by).UserID)
					if err != nil {
						return err
					}
					return audit.Record(w.Ctx, tx, d.as(by).Event(o.ID, "webhook.subscription_disabled", "webhook_subscription", created.ID,
						map[string]any{"url": u}))
				})
			})
		case "auto":
			d.autoDisable(o, &sb)
		}
		d.subs[o.ID] = append(d.subs[o.ID], sb)
	}
}

// autoDisable turns a subscription off the way the dispatcher does after its
// deliveries failed for three days: disabled for "failing", audited as the
// platform's, and every webhook manager alerted in the console's bell.
func (d *dev) autoDisable(o *world.Org, sb *sub) {
	w := d.w
	off := w.Days(sb.spec.since)
	sb.failing = off.Add(-3*24*time.Hour - time.Duration(20+w.Rand.IntN(200))*time.Minute)
	sb.until = off
	w.Exec("webhook auto-disabled", `
		UPDATE tenant.webhook_subscriptions SET failing_since = $3, disabled_at = $4, disabled_reason = 'failing'
		WHERE id = $1 AND tenant_id = $2`, sb.id, o.ID, sb.failing, off)
	id := sb.id
	w.Audit(off, audit.Event{TenantID: &o.ID, ActorType: "system", Action: "webhook.subscription_auto_disabled",
		ResourceType: "webhook_subscription", ResourceID: &id, Metadata: map[string]any{"url": sb.spec.url, "failing_since": sb.failing}})
	desc := "Deliveries to " + sb.spec.url + " failed for 3 days, so the webhook was turned off. Fix the endpoint, then turn the webhook back on."
	managers := people(o, off, builders)
	w.At(off, func() {
		for _, p := range managers {
			w.Check(w.Deps.Notification.Service.Notify(w.Ctx, o.ID, p.ID, "alert", "Webhook turned off", desc, "/developer/webhooks/"+sb.id.String()), "notify "+p.Email)
		}
	})
	for i, p := range managers {
		if i%2 == 0 {
			w.Exec("notification read", `UPDATE auth.notifications SET read_at = $3 WHERE user_id = $1 AND tenant_id = $2 AND href = $4`,
				p.ID, o.ID, off.Add(time.Duration(30+w.Rand.IntN(600))*time.Minute), "/developer/webhooks/"+sb.id.String())
		}
	}
}

// event is one event the organisation emitted: what the relay would hand
// its subscriptions.
type event struct {
	id   uuid.UUID
	typ  string
	at   time.Time
	data json.RawMessage
}

// orgEvents is every catalogue event of the organisation in the delivery
// window: the ones the seed's services emitted into the outbox, and the
// day-to-day ones (sign-outs, password changes, profile syncs, joiners and
// leavers) where no step emitted them.
func (d *dev) orgEvents(o *world.Org, wanted map[string]bool) []event {
	w := d.w
	from := w.Now.Add(-window)
	var out []event
	seen := map[string]bool{}
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT id, event_type, payload, created_at FROM platform.outbox
		WHERE payload->>'tenant_id' = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY created_at`, o.ID.String(), from, w.Now)
	w.Check(err, "read outbox")
	for rows.Next() {
		var e event
		w.Check(rows.Scan(&e.id, &e.typ, &e.data, &e.at), "scan outbox")
		seen[e.typ] = true
		if wanted[e.typ] {
			out = append(out, e)
		}
	}
	rows.Close()
	w.Check(rows.Err(), "read outbox")

	add := func(typ string, at time.Time, data map[string]any) {
		if !wanted[typ] || seen[typ] || at.Before(from) || at.After(w.Now) {
			return
		}
		data["tenant_id"] = o.ID
		b, err := json.Marshal(data)
		w.Check(err, "event payload")
		out = append(out, event{id: uuid.New(), typ: typ, at: at, data: b})
	}
	for _, p := range o.People {
		if p.ID == uuid.Nil {
			continue
		}
		src := p.Provisioned
		if src == "" {
			src = "admin"
		}
		add("user.created", p.Joined, map[string]any{"user_id": p.ID, "email": p.Email, "source": src})
		switch p.Status {
		case world.StatusSuspended:
			add("user.suspended", p.Since, map[string]any{"user_id": p.ID})
		case world.StatusDeleted:
			add("user.deleted", p.Since, map[string]any{"user_id": p.ID})
		}
	}
	active := o.Active()
	for day := 0; day < 14; day++ {
		date := w.Now.Add(-time.Duration(day) * 24 * time.Hour)
		weight := 1.0
		if wd := date.In(o.Loc).Weekday(); wd == time.Saturday || wd == time.Sunday {
			weight = 0.2
		}
		for _, p := range active {
			if p.ID == uuid.Nil || p.Joined.After(date) {
				continue
			}
			at := func() time.Time { return w.WorkHours(date, p.Loc) }
			if w.Chance(0.22 * weight) {
				t := at()
				add("session.revoked", t, map[string]any{"event_id": uuid.New(), "user_id": p.ID, "session_id": uuid.New(),
					"reason": pickReason(w), "revoked_at": t})
			}
			if w.Chance(0.004 * weight) {
				add("auth.password_changed", at(), map[string]any{"user_id": p.ID, "kept_session_id": uuid.New(),
					"revoked_sessions": 1 + w.Rand.IntN(2), "revoked_login_sessions": 0})
			}
			if p.Provisioned == "scim" && w.Chance(0.035*weight) {
				add("user.updated", at(), map[string]any{"user_id": p.ID, "source": "scim"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// pickReason is why a session ended, as often as each happens.
func pickReason(w *world.World) string {
	switch r := w.Rand.Float64(); {
	case r < 0.6:
		return "logout"
	case r < 0.85:
		return "expired"
	case r < 0.9:
		return "other_sessions_revoked"
	case r < 0.94:
		return "password_changed"
	case r < 0.97:
		return "admin_revoked_all"
	default:
		return "session_limit"
	}
}

// delivery is a row of tenant.webhook_deliveries.
type delivery struct {
	id, sub, eventID      uuid.UUID
	typ, payload          string
	status                *int32
	body, err             *string
	attempt               int32
	created               time.Time
	delivered, next, dead *time.Time
}

// deliveries writes the organisation's webhook delivery history: every event
// each subscription took over the last fortnight, delivered while its
// endpoint answered, retrying or dead-lettered since it stopped.
func (d *dev) deliveries(o *world.Org) {
	w := d.w
	subs := d.subs[o.ID]
	if len(subs) == 0 {
		return
	}
	wanted := map[string]bool{}
	for _, s := range subs {
		for _, e := range s.spec.events {
			wanted[e] = true
		}
	}
	events := d.orgEvents(o, wanted)
	var rows [][]any
	for _, s := range subs {
		list := events
		if s.spec.tested > 0 {
			at := w.Now.Add(-time.Duration(s.spec.tested * float64(time.Hour)))
			data, _ := json.Marshal(map[string]any{"subscription_id": s.id})
			list = append(slices.Clone(events), event{id: uuid.New(), typ: webhook.TestEvent, at: at, data: data})
		}
		for _, e := range list {
			if (e.typ != webhook.TestEvent && !slices.Contains(s.spec.events, e.typ)) || e.at.Before(s.from) || !e.at.Before(s.until) {
				continue
			}
			rows = append(rows, d.deliver(o, s, e).row())
		}
	}
	_, err := w.Admin.CopyFrom(w.Ctx, pgx.Identifier{"tenant", "webhook_deliveries"},
		[]string{"id", "subscription_id", "event_id", "event_type", "payload", "status_code", "response_body", "error",
			"attempt", "created_at", "delivered_at", "next_attempt_at", "dead_at"},
		pgx.CopyFromRows(rows))
	w.Check(err, "webhook deliveries of "+o.Spec.Slug)
}

func (r delivery) row() []any {
	return []any{r.id, r.sub, r.eventID, r.typ, r.payload, r.status, r.body, r.err, r.attempt, r.created, r.delivered, r.next, r.dead}
}

// deliver decides how e's delivery to s went.
func (d *dev) deliver(o *world.Org, s sub, e event) delivery {
	w := d.w
	payload, err := json.Marshal(map[string]any{"id": e.id, "type": e.typ, "tenant_id": o.ID, "occurred_at": e.at.UTC(), "data": e.data})
	w.Check(err, "delivery payload")
	created := e.at.Add(time.Duration(40+w.Rand.IntN(900)) * time.Millisecond)
	r := delivery{id: uuid.New(), sub: s.id, eventID: e.id, typ: e.typ, payload: string(payload), created: created}
	if s.failing.IsZero() || created.Before(s.failing) {
		status := int32(s.spec.okStatus)
		r.status, r.attempt = &status, 1
		if s.spec.ok != "" {
			body := s.spec.ok
			r.body = &body
		}
		at := created.Add(time.Duration(120+w.Rand.IntN(700)) * time.Millisecond)
		if w.Chance(0.03) {
			// A blip: the first try failed, the retry got through.
			r.attempt = 2
			at = created.Add(time.Duration(25+w.Rand.IntN(20)) * time.Second)
		}
		r.delivered, r.next = &at, &created
		return r
	}
	// Failing: retried on the dispatcher's schedule until now, or until the
	// subscription was switched off, or dead after the last attempt.
	attempts, last, next, dead := schedule(created, s.until)
	r.attempt = int32(attempts)
	status, body, msg := failure(s.spec, w)
	r.status, r.body, r.err = status, body, &msg
	if dead {
		r.dead = &last
		return r
	}
	if s.until.Equal(w.Now) && next.Before(w.Now.Add(10*time.Minute)) {
		next = w.Now.Add(time.Duration(10+w.Rand.IntN(40)) * time.Minute)
	}
	r.next = &next
	return r
}

// schedule replays the dispatcher's retries of a delivery first tried at
// created, up to until: backoff doubling from 30 s to an hour, jittered, for at
// most 60 attempts. It returns the attempts made, when the last was, when the
// next is due, and whether it was dead-lettered.
func schedule(created, until time.Time) (attempts int, last, next time.Time, dead bool) {
	t := created
	for attempts = 1; ; attempts++ {
		backoff := time.Duration(1<<min(attempts-1, 8)) * 30 * time.Second
		if backoff > time.Hour {
			backoff = time.Hour
		}
		backoff = backoff * 3 / 4
		if attempts >= 60 {
			return attempts, t, time.Time{}, true
		}
		if t.Add(backoff).After(until) {
			return attempts, t, t.Add(backoff), false
		}
		t = t.Add(backoff)
	}
}

// failure is the status, body and error of a failed delivery to s.
func failure(s subSpec, w *world.World) (*int32, *string, string) {
	host := s.url
	if u, err := url.Parse(s.url); err == nil {
		host = u.Hostname()
	}
	switch s.fails {
	case "timeout":
		return nil, nil, `Post "` + s.url + `": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`
	case "dns":
		return nil, nil, `Post "` + s.url + `": resolve outbound destination: lookup ` + host + `: no such host`
	}
	codes := []int32{502, 502, 503, 504}
	code := world.Pick(w, codes)
	bodies := map[int32]string{
		502: "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
		503: "upstream connect error or disconnect/reset before headers. reset reason: connection failure",
		504: "upstream request timeout",
	}
	body := bodies[code]
	return &code, &body, "non-2xx response"
}

// drainOutbox marks every event the seed's services queued as relayed when
// it happened, so the API's outbox relay doesn't deliver months of history to
// today's webhook subscriptions the first time it starts.
func (d *dev) drainOutbox() {
	d.w.Exec("drain the outbox", `UPDATE platform.outbox SET published_at = created_at + interval '2 seconds', attempts = 1 WHERE published_at IS NULL`)
}
