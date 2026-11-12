package integrations

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// decisionSpec is one kind of access decision an organisation's applications
// ask Qeet ID for, answered as the policies the seed gives it answer it.
type decisionSpec struct {
	source string // check, relation_check, authzen or abac_evaluate
	caller string // the application asking, by name ("" an organisation API key)
	about  who    // whom it is about
	// resource is the resource type, with an id in its form when id is set;
	// action is what is asked.
	resource, id, action string
	allowed              bool
	model, rule, reason  string
	weight               int // how often, against the others
}

// Reason codes and rules as the decision engine writes them.
const (
	roleGrant     = "authz.role_grant"
	nothingAllows = "authz.nothing_allows"
	byPolicy      = "authz.allowed_by_policy"
	deniedPolicy  = "authz.denied_by_policy"
	relationGrant = "authz.relation_grant"
)

var anyone who = func(*world.Person) bool { return true }

// decisionSpecs are each organisation's applications' questions over the last
// month. Most are allowed; the refusals are the ones its policies exist for.
var decisionSpecs = map[string][]decisionSpec{
	"qeet": {
		{source: "check", caller: "Qeet Logs", about: dept("Security"), resource: "permission", action: "audit.read",
			allowed: true, model: "rbac", rule: "role grants audit.read", reason: roleGrant, weight: 30},
		{source: "check", caller: "Qeet Logs", about: dept("Sales"), resource: "permission", action: "audit.read",
			model: "none", rule: "nothing allows it", reason: nothingAllows, weight: 4},
		{source: "abac_evaluate", caller: "Qeet Logs", about: dept("Engineering"), resource: "log_stream", id: "prod-%s", action: "read",
			allowed: true, model: "abac", rule: "Engineers read production logs", reason: byPolicy, weight: 40},
		{source: "abac_evaluate", caller: "Qeet Pay Console", about: dept("Operations"), resource: "payout", id: "po_%s", action: "approve",
			model: "abac", rule: "Payouts approved from India only", reason: deniedPolicy, weight: 3},
		{source: "abac_evaluate", caller: "Qeet Pay Console", about: dept("Operations"), resource: "ledger", id: "gl-2026-%s", action: "read",
			model: "abac", rule: "Finance ledgers require MFA", reason: deniedPolicy, weight: 5},
		{source: "abac_evaluate", caller: "Qeet People", about: anyone, resource: "document", id: "handbook-%s", action: "read",
			allowed: true, model: "abac", rule: "Everyone reads the employee handbook", reason: byPolicy, weight: 25},
		{source: "relation_check", caller: "Qeet People", about: dept("Engineering"), resource: "folder:engineering-handbook", action: "viewer",
			allowed: true, model: "rebac", rule: "viewer on folder:engineering-handbook", reason: relationGrant, weight: 12},
		{source: "authzen", caller: "Qeet AI Console", about: dept("Engineering"), resource: "permission", action: "apikey.write",
			allowed: true, model: "rbac", rule: "role grants apikey.write", reason: roleGrant, weight: 8},
	},
	"northwind": {
		{source: "abac_evaluate", caller: "Loan Origination System", about: dept("Credit & Risk"), resource: "loan_application", id: "LA-2026-%s", action: "approve",
			model: "abac", rule: "Loan approvals require MFA", reason: deniedPolicy, weight: 6},
		{source: "abac_evaluate", caller: "Loan Origination System", about: dept("Credit & Risk"), resource: "credit_report", id: "CR-%s", action: "read",
			model: "abac", rule: "Credit bureau data from India only", reason: deniedPolicy, weight: 2},
		{source: "abac_evaluate", caller: "Collections Portal", about: team("Collections"), resource: "loan_account", id: "LN-%s", action: "read",
			allowed: true, model: "abac", rule: "Collections agents see their assigned accounts", reason: byPolicy, weight: 40},
		{source: "check", caller: "Loan Origination System", about: dept("Loan Operations"), resource: "permission", action: "user.read",
			allowed: true, model: "rbac", rule: "role grants user.read", reason: roleGrant, weight: 20},
		{source: "relation_check", caller: "", about: dept("Technology"), resource: "document:readme", action: "viewer",
			allowed: true, model: "rebac", rule: "viewer on document:readme", reason: relationGrant, weight: 6},
	},
	"meridian": {
		{source: "abac_evaluate", caller: "Meridian Staff Portal", about: dept("Clinical Operations"), resource: "patient_record", id: "MRN-%s", action: "read",
			model: "abac", rule: "Charts outside the assigned unit", reason: deniedPolicy, weight: 10},
		{source: "abac_evaluate", caller: "Meridian Staff Portal", about: dept("Clinical Operations"), resource: "patient_record", id: "MRN-%s", action: "read",
			allowed: true, model: "abac", rule: "Break-glass chart access", reason: byPolicy, weight: 2},
		{source: "abac_evaluate", caller: "Meridian Staff Portal", about: title("Physician"), resource: "prescription", id: "RX-%s", action: "sign",
			model: "abac", rule: "E-prescribing requires MFA", reason: deniedPolicy, weight: 3},
		{source: "check", caller: "Meridian Staff Portal", about: dept("Information Technology"), resource: "permission", action: "user.read",
			allowed: true, model: "rbac", rule: "role grants user.read", reason: roleGrant, weight: 25},
	},
	"lumen": {
		{source: "abac_evaluate", caller: "Lumen Cloud", about: anyone, resource: "project", id: "prj_%s", action: "create",
			model: "abac", rule: "Free workspaces: five projects", reason: deniedPolicy, weight: 8},
		{source: "abac_evaluate", caller: "Lumen Cloud", about: dept("Go-to-Market"), resource: "workspace", id: "ws_%s", action: "delete",
			model: "abac", rule: "Staff-only workspace deletion", reason: deniedPolicy, weight: 2},
		{source: "check", caller: "Lumen Cloud", about: dept("Engineering"), resource: "permission", action: "apikey.write",
			allowed: true, model: "rbac", rule: "role grants apikey.write", reason: roleGrant, weight: 30},
	},
}

// decisions writes the access decisions o's applications asked for over the
// last 30 days, as the decision log keeps them: who asked (the application
// by its client ID, or an API key), about whom, and what decided it.
func (d *dev) decisions(o *world.Org) {
	w := d.w
	specs := decisionSpecs[o.Spec.Slug]
	if len(specs) == 0 {
		return
	}
	total := 0
	for _, s := range specs {
		total += s.weight
	}
	callers := map[string][2]string{} // name: caller type, client ID
	for _, s := range specs {
		if _, ok := callers[s.caller]; ok || s.caller == "" {
			continue
		}
		var clientID string
		err := w.Admin.QueryRow(w.Ctx, `SELECT client_id FROM auth.oidc_clients WHERE tenant_id = $1 AND name = $2`, o.ID, s.caller).Scan(&clientID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // the plan's application limit left it out
		}
		w.Check(err, "client of "+s.caller)
		callers[s.caller] = [2]string{"client", clientID}
	}
	people := o.Active()
	batch := &pgx.Batch{}
	n := 6 * total
	for range n {
		s := pickSpec(w, specs, total)
		caller, ok := callers[s.caller]
		if s.caller != "" && !ok {
			continue
		}
		if s.caller == "" {
			caller = [2]string{"api_key", ""}
		}
		p := subject(w, people, s.about)
		if p == nil {
			continue
		}
		resource := s.resource
		if s.id != "" {
			resource += ":" + fmt.Sprintf(s.id, chars(w, "0123456789", 6))
		}
		at := w.WorkHours(w.Between(later(w.Days(30), p.Joined), w.Now.Add(-time.Hour)), p.Loc)
		if at.After(w.Now) {
			continue
		}
		batch.Queue(`INSERT INTO auth.authz_decisions (tenant_id, decided_at, source, caller_type, caller_client, subject, resource, action,
			allowed, model, rule, reason_code) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			o.ID, at, s.source, caller[0], caller[1], p.ID.String(), resource, s.action, s.allowed, s.model, s.rule, s.reason)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "access decisions of "+o.Spec.Slug)
}

// pickSpec picks a spec by weight.
func pickSpec(w *world.World, specs []decisionSpec, total int) decisionSpec {
	n := w.Rand.IntN(total)
	for _, s := range specs {
		if n < s.weight {
			return s
		}
		n -= s.weight
	}
	return specs[len(specs)-1]
}

// subject is a random person among people matching about, or nil.
func subject(w *world.World, people []*world.Person, about who) *world.Person {
	var match []*world.Person
	for _, p := range people {
		if p.ID != uuid.Nil && about(p) {
			match = append(match, p)
		}
	}
	if len(match) == 0 {
		return nil
	}
	return world.Pick(w, match)
}

// later is the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
