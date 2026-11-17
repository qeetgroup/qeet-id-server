package security

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// Address rules in three states: Northwind enforces deny rules only, so
// localhost signs in; Kestrel enforces an office allowlist, so localhost is
// refused; Qeet keeps an allowlist staged, switched off. Ranges are RFC 5737,
// clear of seeded addresses except those a rule is meant to catch.

// ruleSpec is an address rule as an administrator types it.
type ruleSpec struct{ cidr, label, action string }

// enforcedSince is when each organization last switched its address rules on;
// absent while they are off. Compliance evidence reads it.
var enforcedSince = map[string]time.Time{}

// ruleSet is an organization's address rules as they stand.
var ruleSet = map[string][]ipallow.Rule{}

// addressRules writes each organization's address rules and the sign-ins they
// refused.
func addressRules(w *world.World) {
	if o := org(w, "northwind"); o != nil {
		northwindRules(w, o)
	}
	if o := org(w, "kestrel"); o != nil {
		kestrelRules(w, o)
	}
	if o := org(w, "qeet"); o != nil {
		qeetRules(w, o)
	}
}

// northwindRules: after the first credential-stuffing wave the SOC blocks the
// threat feed's ranges, and adds a scanner's range two months later.
func northwindRules(w *world.World, o *world.Org) {
	at := w.WorkHours(o.Spec.Since.Add(100*24*time.Hour), o.Loc)
	ciso := first(o, at, inDept("Information Security", world.RoleAdmin, world.RoleSecurity))
	addRules(w, o, ciso, at, true, []ruleSpec{
		{"192.0.2.240/29", "Credential-stuffing proxies (threat-intel feed, SOC-2026-014)", "deny"},
		{"198.51.100.232/29", "Anonymising VPN exit nodes", "deny"},
		{"203.0.113.248/29", "Tor exit relays (weekly feed)", "deny"},
		{"203.0.113.0/29", "Bulletproof hosting range (CERT-In advisory CIAD-2026-0007)", "deny"},
	})
	later := w.WorkHours(at.Add(64*24*time.Hour), o.Loc)
	analyst := first(o, later, inDept("Information Security", world.RoleSecurity))
	addRules(w, o, analyst, later, false, []ruleSpec{
		{"198.51.100.253/32", "Scanner flagged by Splunk ES (notable 48213)", "deny"},
	})

	// Refused sign-ins from the blocked ranges, a few a day.
	sources := []struct{ ip, ua string }{
		{"192.0.2.242", "python-requests/2.32.3"},
		{"192.0.2.246", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36"},
		{"198.51.100.235", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"},
		{"203.0.113.250", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"},
		{"203.0.113.253", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"},
		{"203.0.113.3", "Go-http-client/2.0"},
		{"198.51.100.253", "masscan/1.3.2"},
	}
	n := 0
	for day := 30; day >= 0; day-- {
		for range w.Rand.IntN(4) {
			t := w.Days(float64(day) + w.Rand.Float64())
			if t.After(w.Now) {
				continue
			}
			s := world.Pick(w, sources)
			if s.ip == "198.51.100.253" && t.Before(later) {
				continue
			}
			refuse(w, o, t, s.ip, "hosted_password", nil)
			n++
		}
	}
	fact(o, "deny rules enforced, no allow rules (localhost signs in), %d refusals in 30 days", n)
}

// kestrelRules: nine days after signing up, the owner allows sign-in only from
// the offices and the office VPN, and blocks the guest Wi-Fi. People trying
// from home or their phones have been refused ever since.
func kestrelRules(w *world.World, o *world.Org) {
	at := w.WorkHours(o.Spec.Since.Add(9*24*time.Hour), o.Loc)
	rules := []ruleSpec{}
	seen := map[string]bool{}
	for _, p := range o.People {
		for _, c := range world.India.Cities {
			if c.Name != p.City || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			label := c.Name + " branch office"
			if c.Name == "Pune" {
				label = "Pune head office — Baner (Airtel leased line)"
			}
			rules = append(rules, ruleSpec{c.Office + "/32", label, "allow"})
		}
	}
	rules = append(rules,
		ruleSpec{"203.0.113.236/32", "Office VPN — FortiGate SSL-VPN (head office)", "allow"},
		ruleSpec{"203.0.113.237/32", "Head office guest Wi-Fi", "deny"},
	)
	addRules(w, o, o.Owner, at, true, rules)

	// Refusals: people at home or on their phones, a visitor on the guest
	// Wi-Fi, and the odd attacker.
	n := 0
	for day := 14; day >= 0; day-- {
		t0 := w.Days(float64(day))
		for range 1 + w.Rand.IntN(4) {
			t := w.WorkHours(t0, o.Loc).Add(time.Duration(w.Rand.IntN(4)) * time.Hour)
			if t.After(w.Now) || t.Before(at) {
				continue
			}
			ps := people(o, t, nil)
			if len(ps) == 0 {
				continue
			}
			p := world.Pick(w, ps)
			switch r := w.Rand.Float64(); {
			case r < 0.35:
				refuse(w, o, t, p.Device.IP, "password", p)
			case r < 0.55:
				refuse(w, o, t, p.Mobile.IP, "hosted_password", nil)
			case r < 0.75:
				refuse(w, o, t, p.Device.IP, "refresh", p)
			case r < 0.85:
				refuse(w, o, t, "203.0.113.237", "hosted_password", nil)
			case r < 0.92:
				refuse(w, o, t, p.Mobile.IP, "passkey", p)
			default:
				refuse(w, o, t, world.Pick(w, world.Attackers).IP, "hosted_password", nil)
			}
			n++
		}
	}
	fact(o, "office allowlist enforced, %d refusals in 14 days", n)
	demos = append(demos, fmt.Sprintf("IP allowlist: every %s member, %s included, is refused from localhost "+
		"(auth.address_not_allowed, after the TOTP step); every other organisation signs in", o.Spec.Name, o.Owner.Email))
}

// qeetRules: the head of security stages an office allowlist, switches it on,
// and switches it off again three hours later when people working from home
// can't sign in. It stays staged.
func qeetRules(w *world.World, o *world.Org) {
	at := w.WorkHours(w.Days(61), o.Loc)
	head := first(o, at, func(p *world.Person) bool { return p.Email == "priya@qeet.in" })
	addRules(w, o, head, at, false, []ruleSpec{
		{"203.0.113.10/32", "Bengaluru HQ — HSR Layout (ACT Fibernet)", "allow"},
		{"192.0.2.10/32", "Berlin — co-working desk (Kreuzberg)", "allow"},
		{"203.0.113.238/32", "Corporate VPN — WireGuard gateway (ap-south-1)", "allow"},
		{"192.0.2.244/30", "Credential-stuffing proxies (threat-intel feed)", "deny"},
	})
	on := at.Add(26 * time.Hour)
	setEnforcement(w, o, head, on, true)
	off := on.Add(3*time.Hour + 10*time.Minute)
	ps := people(o, on, nil)
	for _, p := range ps[:min(6, len(ps))] {
		refuse(w, o, w.Between(on.Add(5*time.Minute), off), p.Device.IP, "refresh", p)
	}
	setEnforcement(w, o, head, off, false)
	fact(o, "office allowlist staged, switched off since %s", off.In(o.Loc).Format("2 Jan"))
}

// addRules adds rules to o as by at at, through the address-rule service,
// switching enforcement on when enable is set, and audits each change.
func addRules(w *world.World, o *world.Org, by *world.Person, at time.Time, enable bool, specs []ruleSpec) {
	svc := w.Deps.IPAllow.Service
	var added []ipallow.Rule
	w.At(at, func() {
		w.Tx("address rules for "+o.Spec.Slug, func(tx pgx.Tx) error {
			for _, r := range specs {
				rule, err := svc.AddRule(w.Ctx, tx, o.ID, r.cidr, r.label, r.action)
				if err != nil {
					return fmt.Errorf("%s: %w", r.cidr, err)
				}
				added = append(added, *rule)
			}
			if enable {
				return svc.SetEnabled(w.Ctx, tx, o.ID, true)
			}
			return nil
		})
	})
	ruleSet[o.Spec.Slug] = append(ruleSet[o.Spec.Slug], added...)
	// One transaction stamps every rule alike; the administrator added them
	// one after another.
	for i, r := range added {
		w.Exec("date an address rule", `UPDATE organization.ip_rules SET created_at = $3 WHERE id = $1 AND organization_id = $2`,
			r.ID, o.ID, at.Add(time.Duration(i)*40*time.Second))
	}
	if enable {
		w.Exec("date address rule enforcement", `UPDATE organization.ip_rules_config SET updated_at = $2 WHERE organization_id = $1`,
			o.ID, at.Add(time.Duration(len(specs))*40*time.Second))
	}
	for i, r := range specs {
		w.Audit(at.Add(time.Duration(i)*40*time.Second), audit.Event{OrganizationID: &o.ID, ActorUserID: &by.ID, Action: "ip_rules.rule_added",
			ResourceType: "ip_rule", IP: by.Device.Office(officeOf(by)).IP, UserAgent: by.Device.UserAgent,
			Metadata: map[string]any{"cidr": r.cidr, "action": r.action}})
	}
	if enable {
		enforcedSince[o.Spec.Slug] = at
		w.Audit(at.Add(time.Duration(len(specs))*40*time.Second), audit.Event{OrganizationID: &o.ID, ActorUserID: &by.ID,
			Action: "ip_rules.enforcement_changed", ResourceType: "ip_rule", IP: by.Device.Office(officeOf(by)).IP,
			UserAgent: by.Device.UserAgent, Metadata: map[string]any{"enabled": true}})
	}
}

// setEnforcement switches o's address rules on or off at at, as by.
func setEnforcement(w *world.World, o *world.Org, by *world.Person, at time.Time, enabled bool) {
	w.At(at, func() {
		w.Tx("address rule enforcement for "+o.Spec.Slug, func(tx pgx.Tx) error {
			return w.Deps.IPAllow.Service.SetEnabled(w.Ctx, tx, o.ID, enabled)
		})
	})
	if enabled {
		enforcedSince[o.Spec.Slug] = at
	} else {
		delete(enforcedSince, o.Spec.Slug)
	}
	w.Audit(at, audit.Event{OrganizationID: &o.ID, ActorUserID: &by.ID, Action: "ip_rules.enforcement_changed", ResourceType: "ip_rule",
		IP: by.Device.Office(officeOf(by)).IP, UserAgent: by.Device.UserAgent, Metadata: map[string]any{"enabled": enabled}})
}

// refuse records the sign-in o's rules refused at t from ip, as the API records
// it (auth.address_refused): the address, the sign-in path, why, and the deny
// rule that matched. who is the account when the path knows it.
func refuse(w *world.World, o *world.Org, t time.Time, ip, path string, who *world.Person) {
	d := ipallow.Decide(ruleSet[o.Spec.Slug], ip)
	if d.Allowed {
		return
	}
	meta := map[string]any{"reason": d.Reason, "path": path, "address": ip}
	var ruleID *uuid.UUID
	if d.Rule != nil {
		ruleID = &d.Rule.ID
		meta["rule_id"] = d.Rule.ID
		meta["cidr"] = d.Rule.CIDR
	}
	var actor *uuid.UUID
	if who != nil {
		actor = &who.ID
	}
	w.Audit(t, audit.Event{OrganizationID: &o.ID, ActorUserID: actor, ActorType: "user", Action: "auth.address_refused",
		ResourceType: "ip_rule", ResourceID: ruleID, IP: ip, Metadata: meta})
}

// officeOf is p's office city.
func officeOf(p *world.Person) world.City {
	for _, l := range []world.Locale{world.India, world.UnitedStates, world.Germany, world.Britain, world.Norway} {
		for _, c := range l.Cities {
			if c.Name == p.City {
				return c
			}
		}
	}
	return world.India.Cities[0]
}
