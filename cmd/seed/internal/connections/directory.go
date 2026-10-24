package connections

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
)

// dirEvent is one provisioning operation of a directory connection, as
// tenant.directory_events records it.
type dirEvent struct {
	id                             uuid.UUID
	conn, op, trigger, kind, resID string
	at                             time.Time
	ms                             int
	status                         int
	outcome                        string // success, warning or failed
	users, groups                  int
	code, message, category, sev   string
	resolution                     string
	resolvedAt                     *time.Time
	resolvedBy, retryOf            *uuid.UUID
}

// directory is one organisation's directory connections being seeded.
type directory struct {
	f      *fed
	o      *world.Org
	times  setup
	scim   string // "scim:<tenant>", or "" for none
	ldap   string // the LDAP connection's ID, or ""
	events []*dirEvent
}

// directories seeds the organisation's LDAP directories and SCIM provisioning:
// connections, tokens, attribute mappings, the profiles they produced, 90
// days of sync activity with its errors, and failure alerts.
func (f *fed) directories(o *world.Org) {
	feat := o.Spec.Features
	if (!feat.SCIM && !feat.LDAP) || !o.Has("enterprise") {
		return
	}
	d := &directory{f: f, o: o, times: f.setupTimes(o)}
	if feat.LDAP {
		d.ldapConnection()
	}
	if feat.SCIM {
		d.scimConnection()
	}
	d.mappings()
	d.profiles()
	d.flush()
	d.alerts()
}

// ldapConnection adds the organisation's directory: Meridian's on-premises
// Active Directory, live since its first clinical sign-in; Qeet's staging
// directory, a draft that never connected.
func (d *directory) ldapConnection() {
	f, w, o := d.f, d.f.w, d.o
	if o.Spec.Slug != "meridian" {
		at := f.around(w.Days(18).Add(-3 * time.Hour))
		server := "ldaps://ldap.staging." + o.Spec.Domain + ":636"
		id := d.createLDAP(adminAt(o, at), at, ldap.CreateInput{
			Name: "Staging Directory (test)", ServerURL: server,
			BindDN: "cn=svc-qeet-id,ou=service,dc=staging,dc=qeet,dc=in", BindPassword: f.token(alnum, 24),
			BaseDN: "ou=people,dc=staging,dc=qeet,dc=in", UserFilter: "(uid=%s)", EmailAttribute: "mail", NameAttribute: "cn",
		})
		d.ldap = id.String()
		// Tested twice on the day it was added, and once since: the host was
		// never published.
		for _, t := range []time.Time{at.Add(25 * time.Minute), at.Add(31 * time.Minute), f.around(w.Days(6))} {
			d.failure(d.ldap, "test", "manual", "connection", "", t, http.StatusBadGateway).message = server + ": no such host"
		}
		return
	}
	by := adminAt(o, d.times.ldapCreated)
	id := d.createLDAP(by, d.times.ldapCreated, ldap.CreateInput{
		Name: "Corporate Active Directory (corp.meridianhealth.us)", ServerURL: "ldaps://dc01.corp.meridianhealth.us:636",
		BindDN:       "CN=svc-qeetid,OU=Service Accounts,OU=IT,DC=corp,DC=meridianhealth,DC=us",
		BindPassword: f.token(alnum+"!#%+", 20), BaseDN: "OU=Staff,DC=corp,DC=meridianhealth,DC=us",
		UserFilter: "(sAMAccountName=%s)", EmailAttribute: "mail", NameAttribute: "displayName",
	})
	d.ldap = id.String()
	// Tested, then switched on.
	d.success(d.ldap, "test", "manual", "connection", "", d.times.ldapActive.Add(-6*time.Minute))
	active := "active"
	w.At(d.times.ldapActive, func() {
		w.Tx("activate LDAP", func(tx pgx.Tx) error {
			_, err := w.Deps.LDAP.Service.Update(w.Ctx, tx, id, o.ID, ldap.UpdateInput{Status: &active})
			return err
		})
	})
	f.record(d.times.ldapActive, o, by, "ldap.connection_updated", "ldap_connection", &id, map[string]any{"status": active})

	// Clinical staff sign in with their directory password: their accounts were
	// made at their first sign-in.
	batch := &pgx.Batch{}
	var clinical []*world.Person
	for _, p := range o.People {
		if p.Provisioned != "ldap" {
			continue
		}
		d.success(d.ldap, "sign-in", "sign-in", "user", p.ID.String(), p.Joined.Add(-900*time.Millisecond))
		batch.Queue(`INSERT INTO "user".external_identities (id, user_id, tenant_id, provider, subject, email, metadata, linked_at)
			VALUES ($1, $2, $3, 'ldap', $4, $5, $6, $7)`, uuid.New(), p.ID, o.ID, p.ExternalID, p.Email,
			map[string]any{"connection": d.ldap}, p.Joined)
		if p.Status == world.StatusActive {
			clinical = append(clinical, p)
		} else if p.Source == "ldap" {
			// Disabled in Active Directory: the next sign-in is refused.
			d.failure(d.ldap, "sign-in", "sign-in", "user", p.ID.String(), later(p.Since.Add(-2*time.Hour), p.Joined.Add(time.Hour)), http.StatusUnauthorized)
		}
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "link LDAP identities")

	// Shift sign-ins over 90 days, a few refused passwords (reviewed by IT),
	// and the newest minutes ago so the connection reads healthy.
	var last time.Time
	for day := 90; day >= 0; day-- {
		for _, p := range clinical {
			if !w.Chance(0.22) {
				continue
			}
			at := w.WorkHours(w.Days(float64(day)), p.Loc)
			if at.Before(p.Joined) || at.After(w.Now.Add(-30*time.Minute)) {
				continue
			}
			if w.Chance(0.02) {
				e := d.failure(d.ldap, "sign-in", "sign-in", "user", p.ID.String(), at, http.StatusUnauthorized)
				if at.Before(w.Days(2)) {
					fixed := at.Add(time.Duration(2+w.Rand.IntN(20)) * time.Hour)
					d.resolve(e, "resolved", fixed, adminAt(o, fixed), "directory.error_resolved")
				}
				continue
			}
			d.success(d.ldap, "sign-in", "sign-in", "user", p.ID.String(), at)
			if at.After(last) {
				last = at
			}
		}
	}
	if len(clinical) > 0 {
		last = f.ago(9*time.Minute, 30*time.Minute)
		d.success(d.ldap, "sign-in", "sign-in", "user", world.Pick(w, clinical).ID.String(), last)
	}
	w.Exec("LDAP last sign-in", `UPDATE tenant.ldap_connections SET last_login_at = $3 WHERE id = $1 AND tenant_id = $2`, id, o.ID, last)

	// Monthly checks; one outage during a domain-controller patch window,
	// retried successfully; one failure this morning, still open; one resolved.
	for day := 80; day > 0; day -= 30 {
		d.success(d.ldap, "test", "manual", "connection", "", w.WorkHours(w.Days(float64(day)), o.Loc))
	}
	admin := adminAt(o, w.Now)
	outage := d.failure(d.ldap, "test", "manual", "connection", "", f.around(w.Now.Add(-(3*24+5)*time.Hour)), http.StatusBadGateway)
	outage.message = "dial tcp: lookup dc01.corp.meridianhealth.us: i/o timeout"
	retry := d.success(d.ldap, "test", "manual", "connection", "", outage.at.Add(47*time.Minute))
	retry.retryOf = &outage.id
	d.resolve(outage, "retried", retry.at, admin, "directory.error_retried")
	open := d.failure(d.ldap, "test", "manual", "connection", "", f.ago(4*time.Hour, 6*time.Hour), http.StatusBadGateway)
	open.message = "LDAP Result Code 200 \"Network Error\": read tcp: connection reset by peer"
	resolved := d.failure(d.ldap, "test", "manual", "connection", "", f.around(w.Now.Add(-(12*24+2)*time.Hour)), http.StatusUnauthorized)
	resolved.message = "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 532"
	d.resolve(resolved, "resolved", resolved.at.Add(3*time.Hour+10*time.Minute), admin, "directory.error_resolved")
}

// createLDAP adds a draft LDAP connection at t, as by.
func (d *directory) createLDAP(by *world.Person, t time.Time, in ldap.CreateInput) uuid.UUID {
	w, o := d.f.w, d.o
	in.Status = "draft"
	var id uuid.UUID
	w.At(t, func() {
		w.Tx("LDAP connection "+in.Name, func(tx pgx.Tx) error {
			c, err := w.Deps.LDAP.Service.Create(w.Ctx, tx, o.ID, in)
			if err == nil {
				id = c.ID
			}
			return err
		})
	})
	d.f.record(t, o, by, "ldap.connection_created", "ldap_connection", &id, map[string]any{"name": in.Name, "server": in.ServerURL})
	return id
}

// scimConnection mints the SCIM token the identity provider pushes with and
// records what it pushed: each provisioned account, membership and profile
// changes, deactivations, and the errors along the way.
func (d *directory) scimConnection() {
	f, w, o := d.f, d.f.w, d.o
	d.scim = "scim:" + o.ID.String()
	by := adminAt(o, d.times.scim)
	token := d.rotate(by, d.times.scim, "user")

	okta := o.Spec.Features.SSO == "okta"
	perDay := 4 // at most, on a working day
	if !okta {
		perDay = 3
	}
	for _, p := range o.People {
		if p.Provisioned != "scim" {
			continue
		}
		d.success(d.scim, "post", "push", "user", "", p.Joined.Add(-400*time.Millisecond))
		if g, ok := o.Groups[team(p)]; ok {
			d.groupEvent(d.scim, "patch", g, p.Joined.Add(time.Duration(40+w.Rand.IntN(200))*time.Second))
		}
		switch {
		case p.Status == world.StatusSuspended && p.Source == "scim":
			d.success(d.scim, "patch", "push", "user", p.ID.String(), p.Since.Add(-2*time.Second))
		case p.Status == world.StatusDeleted:
			d.success(d.scim, "delete", "push", "user", p.ID.String(), p.Since.Add(-2*time.Second))
		}
	}
	// Profile and membership changes over the last 90 days.
	var people []*world.Person
	for _, p := range o.Active() {
		if p.Provisioned == "scim" {
			people = append(people, p)
		}
	}
	for day := 90; day >= 0 && len(people) > 0; day-- {
		at := w.Days(float64(day))
		if wd := at.In(o.Loc).Weekday(); wd == time.Saturday || wd == time.Sunday {
			continue
		}
		for range w.Rand.IntN(perDay) {
			p := world.Pick(w, people)
			t := w.WorkHours(at, o.Loc)
			if t.Before(p.Joined) || t.After(w.Now.Add(-time.Hour)) {
				continue
			}
			if w.Chance(0.3) {
				if g, ok := o.Groups[team(p)]; ok {
					d.groupEvent(d.scim, "patch", g, t)
					continue
				}
			}
			d.success(d.scim, "patch", "push", "user", p.ID.String(), t)
		}
	}

	admin := adminAt(o, w.Now)
	if okta {
		// The token was rotated through the enterprise-setup link; Okta kept
		// the old one for twenty minutes.
		rotated := w.WorkHours(w.Days(47), o.Loc)
		creator := adminAt(o, rotated.Add(-90*time.Minute))
		f.portalUses[o.ID] = portalUse{by: creator, at: rotated}
		token = d.rotate(creator, rotated, "admin_portal")
		var burst []*dirEvent
		for i := range 3 {
			p := world.Pick(w, people)
			burst = append(burst, d.failure(d.scim, "patch", "push", "user", p.ID.String(), rotated.Add(time.Duration(3+i*6)*time.Minute), http.StatusUnauthorized))
		}
		for _, e := range burst {
			d.resolve(e, "resolved", rotated.Add(52*time.Minute), admin, "directory.error_resolved")
		}
		f.alertFired[o.ID] = burst[len(burst)-1].at
		dup := d.failure(d.scim, "post", "push", "user", "", f.around(w.Days(33).Add(-4*time.Hour)), http.StatusConflict)
		dup.message = "userName " + world.Pick(w, people).Email + " is already assigned to an account"
		d.resolve(dup, "resolved", dup.at.Add(2*time.Hour), admin, "directory.error_resolved")
		limited := d.failure(d.scim, "patch", "push", "group", "", f.around(w.Now.Add(-(2*24+3)*time.Hour)), http.StatusTooManyRequests)
		limited.message = "Rate limit exceeded while pushing group memberships; Okta will retry"
		bad := d.failure(d.scim, "patch", "push", "user", world.Pick(w, people).ID.String(), f.around(w.Now.Add(-26*time.Hour)), http.StatusBadRequest)
		bad.message = "Unsupported attribute urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter"
		partial := d.groupEvent(d.scim, "patch", o.Groups[world.Pick(w, o.Spec.Depts).Name], f.around(w.Now.Add(-(6*24+1)*time.Hour)))
		partial.outcome, partial.sev, partial.category, partial.code = "warning", "warning", "provisioning", "DIR-PARTIAL"
		partial.message = "Group membership pushed; 2 members are not assigned to the application and were skipped"
	} else {
		missing := d.failure(d.scim, "patch", "push", "user", uuid.NewString(), f.around(w.Days(21).Add(-5*time.Hour)), http.StatusNotFound)
		d.resolve(missing, "resolved", missing.at.Add(26*time.Hour), admin, "directory.error_resolved")
		var phone []*dirEvent
		burst := f.around(w.Now.Add(-36 * time.Hour))
		for i := range 2 {
			e := d.failure(d.scim, "patch", "push", "user", world.Pick(w, people).ID.String(), burst.Add(time.Duration(i*4)*time.Minute), http.StatusBadRequest)
			e.message = "Attribute 'phoneNumbers[type eq \"mobile\"].value' is not a valid E.164 number"
			phone = append(phone, e)
		}
		f.alertFired[o.ID] = phone[1].at
		warn := d.success(d.scim, "put", "push", "user", world.Pick(w, people).ID.String(), f.around(w.Now.Add(-(4*24+6)*time.Hour)))
		warn.outcome, warn.sev, warn.category, warn.code = "warning", "warning", "validation", "DIR-TRUNCATED"
		warn.message = "Provisioned with a warning: jobTitle was longer than 128 characters and was truncated"
	}
	// The newest push, minutes ago, so the connection reads healthy.
	if len(people) > 0 {
		last := f.ago(14*time.Minute, 44*time.Minute)
		d.success(d.scim, "patch", "push", "user", world.Pick(w, people).ID.String(), last)
		w.Exec("SCIM token last use", `UPDATE tenant.scim_tokens SET last_used_at = $2 WHERE tenant_id = $1`, o.ID, last)
	}
	f.scim = append(f.scim, scimNote{org: o.Spec.Name, token: token})
}

// rotate mints a new SCIM token at t; via "admin_portal" when the identity
// provider's administrator did it through an enterprise-setup link.
func (d *directory) rotate(by *world.Person, t time.Time, via string) string {
	w, o := d.f.w, d.o
	var token string
	w.At(t, func() {
		w.Tx("SCIM token", func(tx pgx.Tx) error {
			var err error
			token, err = w.Deps.SCIM.Service.Rotate(w.Ctx, tx, o.ID)
			return err
		})
	})
	e := d.f.event(o, by, "scim.token_rotated", "scim_token", nil, nil)
	e.ActorType = via
	w.Audit(t, e)
	return token
}

// team is the group p belongs to: their team, or their department when they
// lead it.
func team(p *world.Person) string {
	if p.Team != "" {
		return p.Team
	}
	return p.Department
}

// success records a successful operation at t.
func (d *directory) success(conn, op, trigger, kind, resID string, t time.Time) *dirEvent {
	e := &dirEvent{id: uuid.New(), conn: conn, op: op, trigger: trigger, kind: kind, resID: resID, at: t,
		ms: d.duration(op), status: http.StatusOK, outcome: "success", message: "Operation completed", resolution: "open"}
	if op == "post" {
		e.status = http.StatusCreated
	}
	if op == "delete" {
		e.status = http.StatusNoContent
	}
	if kind == "user" {
		e.users = 1
	}
	d.events = append(d.events, e)
	return e
}

// groupEvent records a successful membership push for group at t.
func (d *directory) groupEvent(conn, op string, group uuid.UUID, t time.Time) *dirEvent {
	e := d.success(conn, op, "push", "group", group.String(), t)
	e.groups = 1
	return e
}

// failure records an operation refused with status at t, classified as the
// API classifies it.
func (d *directory) failure(conn, op, trigger, kind, resID string, t time.Time, status int) *dirEvent {
	e := &dirEvent{id: uuid.New(), conn: conn, op: op, trigger: trigger, kind: kind, resID: resID, at: t,
		ms: d.duration(op), status: status, outcome: "failed", resolution: "open",
		code: "DIR-" + strconv.Itoa(status), category: "provisioning", sev: "warning"}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.category, e.message, e.sev = "permission", "Directory access was denied", "critical"
	case status == http.StatusConflict:
		e.message = "An identity or group already exists"
	case status == http.StatusNotFound:
		e.message = "The requested directory object was not found"
	case status == http.StatusTooManyRequests:
		e.category, e.message = "limit", "The directory request limit was reached"
	case status >= 500:
		e.category, e.message, e.sev = "connection", "The directory operation could not be completed", "critical"
		e.ms = 10000 + d.f.w.Rand.IntN(5000)
	default:
		e.category, e.message = "validation", "The directory request could not be validated"
	}
	d.events = append(d.events, e)
	return e
}

// resolve marks e resolved or retried by by at t, as the error screen's
// buttons do.
func (d *directory) resolve(e *dirEvent, resolution string, t time.Time, by *world.Person, action string) {
	e.resolution, e.resolvedAt = resolution, &t
	id := by.ID
	e.resolvedBy = &id
	d.f.record(t, d.o, by, action, "directory_error", &e.id, map[string]any{"success": true})
}

// duration is a plausible time for op, in milliseconds.
func (d *directory) duration(op string) int {
	r := d.f.w.Rand
	switch op {
	case "test":
		return 140 + r.IntN(900)
	case "sign-in":
		return 90 + r.IntN(500)
	default:
		return 35 + r.IntN(320)
	}
}

// flush writes the recorded events, oldest first.
func (d *directory) flush() {
	w, o := d.f.w, d.o
	// In time order, so a retry follows the failure it retried.
	sort.SliceStable(d.events, func(i, j int) bool { return d.events[i].at.Before(d.events[j].at) })
	batch := &pgx.Batch{}
	for _, e := range d.events {
		batch.Queue(`INSERT INTO tenant.directory_events
			(id, tenant_id, connection_id, operation, trigger_type, resource_type, resource_id, started_at, duration_ms,
			 http_status, status, users_synced, groups_synced, error_code, message, category, severity,
			 resolution, resolved_at, resolved_by, retry_of)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
			e.id, o.ID, e.conn, e.op, e.trigger, e.kind, e.resID, e.at.UTC(), e.ms, e.status, e.outcome, e.users, e.groups,
			e.code, e.message, e.category, e.sev, e.resolution, e.resolvedAt, e.resolvedBy, e.retryOf)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "directory events for "+o.Spec.Slug)
}

// mapping is an attribute mapping rule.
type mapping struct {
	source, target, kind, transform, pattern string
	enabled, required                        bool
}

// enterprise is the SCIM enterprise-user extension's attribute prefix.
const enterprise = "/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User/"

// mappings sets each connection's attribute mappings, as the IT administrator
// did after connecting it.
func (d *directory) mappings() {
	if d.scim != "" {
		d.saveMappings(d.scim, d.times.scim.Add(35*time.Minute), []mapping{
			{"userName", "email", "string", "lowercase", "", true, true},
			{"displayName", "display_name", "string", "trim", "", true, false},
			{"/name/givenName", "first_name", "string", "trim", "", true, false},
			{"/name/familyName", "last_name", "string", "trim", "", true, false},
			{"title", "title", "string", "trim", "", true, false},
			{enterprise + "department", "department", "string", "none", "", true, false},
			{enterprise + "manager/value", "manager_id", "string", "none", "", true, false},
			{enterprise + "division", "department", "string", "uppercase", "", false, false},
		})
	}
	if d.ldap != "" && d.o.Spec.Slug == "meridian" {
		d.saveMappings(d.ldap, d.times.ldapActive.Add(-12*time.Minute), []mapping{
			{"mail", "email", "string", "lowercase", "", true, true},
			{"displayName", "display_name", "string", "trim", "", true, false},
			{"givenName", "first_name", "string", "none", "", true, false},
			{"sn", "last_name", "string", "none", "", true, false},
			{"title", "title", "string", "trim", "", true, false},
			{"department", "department", "string", "trim", "", true, false},
			{"manager", "manager_id", "string", "extract", `^CN=([^,]+),`, true, false},
			{"memberOf", "groups", "array", "extract", `^CN=([^,]+),`, true, false},
		})
	}
}

// saveMappings writes rules for conn at t. A required rule started optional:
// the administrator made it required a month later.
func (d *directory) saveMappings(conn string, t time.Time, rules []mapping) {
	f, w, o := d.f, d.f.w, d.o
	by := adminAt(o, t)
	upd := w.WorkHours(t.Add(30*24*time.Hour), o.Loc)
	for i, m := range rules {
		at := t.Add(time.Duration(i*40+w.Rand.IntN(30)) * time.Second)
		id := uuid.New()
		w.Exec("mapping "+m.target, `INSERT INTO tenant.directory_mappings
			(id, tenant_id, connection_id, source_attribute, target_field, value_type, transform, pattern, enabled, required, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, 1, $10, $10)`,
			id, o.ID, conn, m.source, m.target, m.kind, m.transform, m.pattern, m.enabled, at)
		f.record(at, o, by, "directory.mapping_created", "directory_mapping", &id, nil)
		if m.required && upd.Before(w.Now.Add(-time.Hour)) {
			w.Exec("mapping update", `UPDATE tenant.directory_mappings SET required = true, version = 2, updated_at = $3 WHERE id = $1 AND tenant_id = $2`, id, o.ID, upd)
			f.record(upd, o, adminAt(o, upd), "directory.mapping_updated", "directory_mapping", &id, nil)
		}
	}
}

// profiles stores the profile each provisioned account's directory mapped,
// as the last full sync left it.
func (d *directory) profiles() {
	w, o := d.f.w, d.o
	at := d.f.ago(3*time.Hour, 7*time.Hour)
	w.At(at, func() {
		w.Tx("directory profiles", func(tx pgx.Tx) error {
			for _, p := range o.People {
				if p.Status == world.StatusDeleted || p.Provisioned == "" {
					continue
				}
				conn := d.scim
				profile := map[string]any{"email": p.Email, "display_name": p.Name(), "first_name": p.First, "last_name": p.Last,
					"title": p.Title, "department": p.Department}
				if p.Provisioned == "ldap" {
					conn = d.ldap
					groups := []string{"Clinical-Staff", "EPIC-Users"}
					if p.Team != "" {
						groups = append(groups, strings.ReplaceAll(p.Team, " ", "-"))
					}
					profile["groups"] = groups
					if p.Manager != nil {
						profile["manager_id"] = p.Manager.Name()
					}
				} else if p.Manager != nil && p.Manager.ExternalID != "" {
					profile["manager_id"] = p.Manager.ExternalID
				}
				if conn == "" {
					continue
				}
				if err := w.Deps.Directory.Service.StoreProfile(w.Ctx, tx, o.ID, p.ID, conn, profile); err != nil {
					return fmt.Errorf("profile of %s: %w", p.Email, err)
				}
			}
			return nil
		})
	})
}

// alerts adds the IT team's failure alerts, and the notification each one
// that fired sent.
func (d *directory) alerts() {
	w, o := d.f.w, d.o
	if d.scim == "" && o.Spec.Slug != "meridian" {
		return // nothing live to watch
	}
	type alert struct {
		name      string
		conn      *string
		threshold int
		enabled   bool
	}
	var list []alert
	if d.scim != "" {
		name, threshold := "Okta provisioning failures", 3
		if o.Spec.Features.SSO == "entra" {
			name, threshold = "Entra ID provisioning errors", 2
		}
		scim := d.scim
		list = append(list, alert{name, &scim, threshold, true})
	}
	if d.ldap != "" && o.Spec.Slug == "meridian" {
		conn := d.ldap
		list = append(list, alert{"Active Directory outage", &conn, 5, true})
	}
	list = append(list, alert{"Any directory failure (noisy)", nil, 10, false})
	created := w.WorkHours(later(d.times.scim, d.times.ldapActive).Add(9*24*time.Hour), o.Loc)
	owner := adminAt(o, created)
	for i, a := range list {
		var notified *time.Time
		if fired, ok := d.f.alertFired[o.ID]; ok && i == 0 && fired.After(created) {
			t := fired.Add(20 * time.Second)
			notified = &t
		}
		w.Exec("directory alert "+a.name, `INSERT INTO tenant.directory_alerts
			(id, tenant_id, user_id, name, connection_id, threshold, enabled, created_at, last_notified_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			uuid.New(), o.ID, owner.ID, a.name, a.conn, a.threshold, a.enabled, created.Add(time.Duration(i)*time.Minute), notified)
		if notified != nil {
			read := notified.Add(47 * time.Minute)
			var readAt *time.Time
			if read.Before(w.Days(1)) {
				readAt = &read
			}
			w.Exec("alert notification", `INSERT INTO auth.notifications (id, user_id, tenant_id, kind, title, description, href, created_at, read_at)
				VALUES ($1, $2, $3, 'warning', $4, $5, '/directory/sync-errors', $6, $7)`,
				uuid.New(), owner.ID, o.ID, a.name, "Directory failures reached your alert threshold in the last 15 minutes.", *notified, readAt)
		}
	}
}
