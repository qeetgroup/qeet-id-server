package accounts

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// risks is how risky each suspension reason looks to the reviewer.
var risks = map[string]string{
	"suspicious_activity": "high",
	"account_compromise":  "high",
	"policy_violation":    "medium",
	"offboarding":         "low",
	"inactive":            "low",
}

// reasonText is a suspension reason in a sentence.
var reasonText = map[string]string{
	"suspicious_activity": "suspicious sign-in activity",
	"account_compromise":  "a suspected account compromise",
	"policy_violation":    "a policy violation",
	"offboarding":         "offboarding",
	"inactive":            "inactivity",
	"provider":            "the identity provider deactivated it",
}

// accounts carries out the account states the census decided, each on its
// date and through the path that would have made it: an administrator's
// suspension or deletion in the console, the identity provider's SCIM
// deactivation, the directory sync, or the inactivity policy. Suspensions are
// then triaged in the review queue; the newest are still pending.
func (s *seeder) accounts(o *world.Org) {
	for _, p := range o.People {
		switch p.Status {
		case world.StatusSuspended:
			s.suspend(o, p)
		case world.StatusDeleted:
			s.remove(o, p)
		}
	}
}

// suspend suspends p on p.Since the way p.Source names, then records the
// review of it.
func (s *seeder) suspend(o *world.Org, p *world.Person) {
	w := s.w
	path := "/users/" + p.ID.String()
	switch p.Source {
	case "scim", "ldap":
		s.deactivate(o, p, p.Since, p.Source)
	case "policy":
		w.At(p.Since, func() { s.api.do(o, nil, "system", "PATCH", path, map[string]any{"status": "suspended"}) })
		w.Exec("suspended by policy "+p.Email, `UPDATE "user".users SET suspension_source = 'policy', suspension_reason = $3
			WHERE id = $1 AND tenant_id = $2`, p.ID, o.ID, p.Reason)
	default:
		actor := by(o, p.Since, world.RoleSecurity, world.RoleITAdmin, world.RoleAdmin)
		w.At(p.Since, func() {
			s.api.do(o, actor, "", "PATCH", path, map[string]any{"status": "suspended"})
		})
	}

	// The review: reason and risk recorded within the day; closed after a
	// week or two, except where an investigation is still open.
	reviewed := p.Since.Before(w.Days(10)) && risks[p.Reason] != "high"
	at := clamp(w, p.Since.Add(time.Duration(40+w.Rand.IntN(5*60))*time.Minute))
	reviewer := by(o, at, world.RoleSecurity, world.RoleITAdmin, world.RoleAdmin)
	review := "pending"
	if reviewed {
		review = "reviewed"
	}
	if p.Source != "policy" || reviewed {
		body := map[string]any{"reason": p.Reason, "risk": risks[p.Reason], "review": review}
		w.At(at, func() { s.api.do(o, reviewer, "", "PUT", path+"/suspension", body) })
	}
	s.tell(o, event{at: p.Since.Add(time.Minute), kind: "warning", title: "Account suspended: " + p.Name(),
		detail: fmt.Sprintf("%s was suspended for %s. Review it in the suspended accounts queue.", p.Email, reasonText[p.Reason]),
		href:   "/users/suspended", security: true, helpdesk: true})
}

// deactivate suspends p as their identity provider does: SCIM sets active to
// false (recorded as a SCIM update, reason "provider"), and the directory sync
// disables an account removed from Active Directory.
func (s *seeder) deactivate(o *world.Org, p *world.Person, at time.Time, source string) {
	w := s.w
	action, reason := "user.updated", "provider"
	meta := map[string]any{"status": "suspended"}
	ip, ua := "198.51.100.235", "Okta SCIM Client 1.0.0"
	if o.Spec.Features.SSO == "entra" {
		ip, ua = "198.51.100.236", "Microsoft Azure AD SCIM Client"
	}
	if source == "ldap" {
		action, reason, ip, ua = "user.suspended", p.Reason, "", ""
		meta = map[string]any{"reason": "account disabled in Active Directory", "dn": p.ExternalID}
	}
	if reason == "" {
		reason = "other"
	}
	w.At(at, func() {
		w.Tx("deactivate "+p.Email, func(tx pgx.Tx) error {
			suspended := "suspended"
			if _, err := w.Deps.User.Repo.UpdateTx(w.Ctx, tx, p.ID, user.UpdateInput{Status: &suspended}); err != nil {
				return err
			}
			if _, err := tx.Exec(w.Ctx, `UPDATE "user".users SET suspension_source = $3, suspension_reason = $4
				WHERE id = $1 AND tenant_id = $2`, p.ID, o.ID, source, reason); err != nil {
				return err
			}
			id := p.ID
			return audit.Record(w.Ctx, tx, audit.Event{TenantID: &o.ID, ActorType: source, Action: action,
				ResourceType: "user", ResourceID: &id, IP: ip, UserAgent: ua, Metadata: meta})
		})
	})
}

// remove soft-deletes a leaver in the console, recording who did it. Where
// the identity provider manages the account it deactivated it the day before.
func (s *seeder) remove(o *world.Org, p *world.Person) {
	w := s.w
	if p.Provisioned == "scim" || p.Provisioned == "ldap" {
		s.deactivate(o, p, p.Since.Add(-time.Duration(18+w.Rand.IntN(30))*time.Hour), p.Provisioned)
	}
	actor := by(o, p.Since, world.RoleITAdmin, world.RoleAdmin)
	w.At(p.Since, func() { s.api.do(o, actor, "", "DELETE", "/users/"+p.ID.String(), nil) })
	s.tell(o, event{at: p.Since.Add(time.Minute), kind: "info", title: "Account deleted: " + p.Name(),
		detail: fmt.Sprintf("%s deleted %s's account. It can be restored from Deleted users until it is purged.", actor.Name(), p.Email),
		href:   "/users/deleted", helpdesk: true})
}

// enrolmentDemo makes one Qeet Group account, with no second factor yet,
// required to set one up: its next sign-in shows the MFA enrolment screen.
// It joins the test accounts in the summary.
func (s *seeder) enrolmentDemo() {
	w := s.w
	var o *world.Org
	for _, org := range w.Orgs {
		if org.Spec.Slug == "qeet" {
			o = org
		}
	}
	if o == nil {
		return
	}
	// A Sales or Customer Success member who joined a while ago and never set
	// up a second factor.
	var p *world.Person
	for _, dept := range []string{"Sales", "Customer Success", ""} {
		for _, c := range o.Active() {
			if p == nil && c.Login == "" && len(c.MFA) == 0 && !c.Unverified && c.Provisioned == "" &&
				c.Role != world.RoleOwner && c.Joined.Before(w.Days(30)) && (dept == "" || c.Department == dept) {
				p = c
			}
		}
	}
	if p == nil {
		return
	}
	at := w.Days(1.6)
	admin := by(o, at, world.RoleAdmin)
	if sec := o.Person("priya@qeet.in"); sec != nil && sec.Status == world.StatusActive {
		admin = sec
	}
	w.At(at, func() {
		s.api.do(o, admin, "", "PUT", "/users/"+p.ID.String()+"/mfa-required", map[string]any{"required": true})
	})
	p.Login = roleName(p.Role) + " — must set up MFA at next sign-in (QR code + recovery codes)"
	s.enrol = &enrolment{person: p, at: at, by: admin}
}
