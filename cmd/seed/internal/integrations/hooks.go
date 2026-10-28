package integrations

import (
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	authhook "github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
)

// hookSpec is a post-login hook, and the changes made to it since. Only the
// oldest enabled hook runs at sign-in, and every enabled one fails open, so
// an unreachable seeded host never refuses a tester (it adds a DNS miss, a
// few milliseconds, and an auth_hook.skipped record); the fail-closed ones are
// switched off. Qeet Group's is paused, so its testers' sign-ins stay quiet.
type hookSpec struct {
	url      string
	failOpen bool
	by       []who
	created  float64
	changes  []hookChange
}

// hookChange sets a hook's enabled and fail-open flags days ago.
type hookChange struct {
	days              float64
	enabled, failOpen bool
}

// hookSpecs are each organisation's post-login hooks, on hosts that do not
// resolve.
var hookSpecs = map[string][]hookSpec{
	"qeet": {
		{url: "https://risk.qeet.in/v1/login-decision", failOpen: false, by: []who{email("rohan@qeet.in")}, created: 220,
			changes: []hookChange{{days: 150, enabled: false, failOpen: false}}},
		{url: "https://hooks.qeet.in/qeet-id/post-login/claims", failOpen: true, by: []who{email("rohan@qeet.in")}, created: 160,
			changes: []hookChange{{days: 6, enabled: false, failOpen: true}}},
	},
	"northwind": {
		{url: "https://fraud-gateway.northwindcapital.in/v2/login-screen", failOpen: false, by: []who{both(team("Platform Engineering"), builders)}, created: 300,
			changes: []hookChange{{days: 210, enabled: false, failOpen: false}}},
		{url: "https://risk-engine.northwindcapital.in/qeet/post-login", failOpen: false, by: []who{both(team("Platform Engineering"), builders)}, created: 205,
			changes: []hookChange{{days: 118, enabled: true, failOpen: true}}},
	},
	"meridian": {
		{url: "https://iam-hooks.meridianhealth.us/qeet/post-login", failOpen: true, by: []who{email("jennifer.walsh@meridianhealth.us")}, created: 180},
	},
	"lumen": {
		{url: "https://api.lumenlabshq.dev/internal/hooks/post-login", failOpen: true, by: []who{both(team("Core Platform"), builders)}, created: 100,
			changes: []hookChange{{days: 30, enabled: false, failOpen: true}}},
	},
}

// authHooks creates the organisation's post-login hooks through the auth
// hook service, then changes them as their story goes.
func (d *dev) authHooks(o *world.Org) {
	w := d.w
	for _, s := range hookSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		var h *authhook.Hook
		w.At(at, func() {
			var err error
			h, err = w.Deps.AuthHook.Service.Create(w.Ctx, o.ID, s.url, "whsec_"+token(w, 32), s.failOpen, d.as(by))
			w.Check(err, "auth hook "+s.url)
		})
		for _, c := range s.changes {
			ct := d.when(o, c.days, by)
			editor := person(o, ct, email(by.Email), both(dept("Security"), guardians), both(dept("Information Security"), guardians))
			w.At(ct, func() {
				_, _, err := w.Deps.AuthHook.Service.Update(w.Ctx, h.ID, o.ID, authhook.HookSettings{Enabled: &c.enabled, FailOpen: &c.failOpen}, d.as(editor))
				w.Check(err, "change auth hook "+s.url)
			})
		}
	}
}

// sinkSpec is a log stream to a SIEM and its health today: forwarding, failing
// with lastError since it last forwarded, or switched off.
type sinkSpec struct {
	typ, endpoint string
	token         func(w *world.World) string
	by            []who
	created       float64
	forwarded     float64 // days since it last forwarded
	lastError     string
	disabled      float64 // days ago; 0 still streaming
}

// sinkSpecs are each organisation's log streams. No endpoint is a vendor's
// own intake host: each goes through a relay on the organisation's domain,
// which does not resolve.
var sinkSpecs = map[string][]sinkSpec{
	"qeet": {
		{typ: "http", endpoint: "https://ingest.logs.qeet.in/v1/http/qeet-id", token: prefixed("qlog_", 40),
			by: []who{both(team("Site Reliability"), builders)}, created: 230, forwarded: 0.0005},
	},
	"northwind": {
		{typ: "http", endpoint: "https://arcsight-sc.northwindcapital.in/receiver/v1/events", token: hexed(32),
			by: []who{both(dept("Information Security"), builders)}, created: 330, forwarded: 120.01, disabled: 120},
		{typ: "splunk_hec", endpoint: "https://splunk-hec.northwindcapital.in:8088/services/collector/event",
			token: func(w *world.World) string { return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(token(w, 12))).String() },
			by:    []who{both(dept("Information Security"), builders)}, created: 145, forwarded: 0.0009},
	},
	"meridian": {
		{typ: "datadog", endpoint: "https://dd-relay.meridianhealth.us/api/v2/logs", token: hexed(32),
			by: []who{both(dept("Security"), builders)}, created: 200, forwarded: 2.2, lastError: "sink returned 403"},
	},
}

// logSinks creates the organisation's log streams through the SIEM service
// and sets how far each has forwarded.
func (d *dev) logSinks(o *world.Org) {
	w := d.w
	for _, s := range sinkSpecs[o.Spec.Slug] {
		days := d.jitter(s.created)
		at := d.when(o, days)
		by := person(o, at, s.by...)
		at = d.when(o, days, by)
		var sk *siem.Sink
		w.At(at, func() {
			var err error
			sk, err = w.Deps.SIEM.Service.Create(w.Ctx, o.ID, s.typ, s.endpoint, s.token(w), d.as(by))
			w.Check(err, "log sink "+s.endpoint)
		})
		if s.disabled > 0 {
			dt := d.when(o, s.disabled, by)
			w.At(dt, func() {
				w.Check(w.Deps.SIEM.Service.SetEnabled(w.Ctx, sk.ID, o.ID, false, d.as(by)), "disable log sink "+s.endpoint)
			})
		}
		// The cursor is at the story's present, so the API forwards only what
		// happens from now on, and a seeded error stands until then.
		w.Exec("log sink progress", `
			UPDATE tenant.log_sinks SET last_forwarded_at = $3, last_error = $4, cursor_created_at = $5, cursor_id = $6
			WHERE id = $1 AND tenant_id = $2`, sk.ID, o.ID, w.Days(s.forwarded), s.lastError, w.Now, uuid.Max)
	}
}
