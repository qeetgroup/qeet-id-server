package world

import (
	"slices"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
)

// OrgSpec describes a seeded organization: who it is and how it uses Qeet ID.
// Every step reads it, so the organizations stay consistent across screens.
type OrgSpec struct {
	Slug, Name string
	Domain     string // email domain; never resolves, so nothing seeded reaches a real host
	Industry   string
	City       string // headquarters, e.g. "Mumbai"
	Country    string // ISO 3166-1 alpha-2
	Region     string // data region
	Plan       string // free | starter | pro | enterprise
	Currency   string
	// Billing is the subscription's state: active (paid), trialing, unpaid
	// (its invoice is open) or canceled (ends with the period).
	Billing  string
	Size     int      // people whose home is the organization, owner included
	Locales  []Locale // where its people come from, weighted by repetition
	Brand    Brand
	Features Features
	Depts    []Dept
	Story    string // one line on the organization, for the summary
}

// Brand is an organization's look on the hosted pages.
type Brand struct {
	Primary, Secondary, Background string // #rrggbb
}

// Features is how an organization signs its people in and connects its
// systems. A feature its plan lacks is never set.
type Features struct {
	SSO         string   // SAML identity provider: okta, entra, google, or "" for none
	SSOStatus   string   // active | draft
	SCIM        bool     // people provisioned from the identity provider
	LDAP        bool     // an on-premises directory
	Social      []string // organization social providers
	MagicLink   bool
	Passkeys    bool
	SelfSignup  bool   // hosted self-registration
	MFA         string // optional | admin_only | required
	MFAGrace    int    // days a person may put off enrolling
	IPAllowlist bool   // sign-in only from office addresses
	Webhooks    bool
	Apps        []string // kinds of OIDC applications: web, spa, native, device, m2m
}

// Dept is a department and its teams, with the titles people in it hold.
type Dept struct {
	Name   string
	Teams  []string
	Titles []string // repeated titles are the more common
	Share  int      // relative headcount
	Head   string   // the department head's title
	Role   string   // the role its people hold
}

// Org is a seeded organization.
type Org struct {
	Spec   OrgSpec
	ID     uuid.UUID
	Owner  *Person
	People []*Person // home members, owner first
	Guests []*Person // members whose home is another organization
	Roles  map[string]uuid.UUID
	Groups map[string]uuid.UUID // department and team names
}

// Has reports whether the organization's plan includes a paid feature.
func (o *Org) Has(plan string) bool {
	rank := map[string]int{"free": 0, "starter": 1, "pro": 2, "enterprise": 3}
	return rank[o.Spec.Plan] >= rank[plan]
}

// Active is the organization's people who can sign in today.
func (o *Org) Active() []*Person {
	var out []*Person
	for _, p := range o.People {
		if p.Status == StatusActive {
			out = append(out, p)
		}
	}
	return out
}

// First is the first active person, guests included, matching one of prefs
// (tried in order), else the owner.
func (o *Org) First(prefs ...func(*Person) bool) *Person {
	for _, pref := range prefs {
		for _, p := range append(o.Active(), o.Guests...) {
			if pref(p) {
				return p
			}
		}
	}
	return o.Owner
}

// Admin is who makes an administrative change in o: an IT administrator,
// else an Admin, else the owner.
func (o *Org) Admin() *Person { return o.First(HasRole(RoleITAdmin), HasRole(RoleAdmin)) }

// Person returns the organization's person with email, or nil.
func (o *Org) Person(email string) *Person {
	for _, p := range o.People {
		if p.Email == email {
			return p
		}
	}
	return nil
}

// HasRole matches people holding one of roles in their home organization.
func HasRole(roles ...string) func(*Person) bool {
	return func(p *Person) bool { return slices.Contains(roles, p.Role) }
}

// InDept matches people in dept.
func InDept(dept string) func(*Person) bool {
	return func(p *Person) bool { return p.Department == dept }
}

// InTeam matches people in team.
func InTeam(team string) func(*Person) bool {
	return func(p *Person) bool { return p.Team == team }
}

// Email matches the person with address e.
func Email(e string) func(*Person) bool {
	return func(p *Person) bool { return p.Email == e }
}

// Role names every organization on a paid plan has. Free plans allow no custom
// role, so their people all hold the system owner role.
const (
	RoleOwner     = "owner"
	RoleAdmin     = "Admin"
	RoleITAdmin   = "IT Admin"
	RoleHelpdesk  = "Helpdesk"
	RoleSecurity  = "Security Analyst"
	RoleAuditor   = "Auditor"
	RoleDeveloper = "Developer"
	RoleBilling   = "Billing Admin"
	RoleMember    = "Member"
)

// Account states.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted" // soft-deleted
)

// Person is a seeded account, homed in Org.
type Person struct {
	ID         uuid.UUID
	Org        *Org
	First      string
	Last       string
	Email      string
	Title      string
	Department string
	Team       string
	City       string
	Country    string // ISO 3166-1 alpha-2
	Phone      string // E.164 from a fictional range; empty for some
	EmployeeID string
	Manager    *Person
	Role       string // role in the home organization
	// GuestOf are the roles held in other organizations.
	GuestOf []GuestRole

	// Status is the account's state today; Reason is why it was suspended.
	Status, Reason string
	Unverified     bool   // has never verified the email address
	Provisioned    bool   // pushed by the identity provider over SCIM
	ExternalID     string // the identity provider's id, for provisioned accounts

	// MFA lists the factors to enrol: totp, recovery, push. TOTPSecret and
	// RecoveryCodes are what the enrolment returned.
	MFA           []string
	TOTPSecret    string
	RecoveryCodes []string
	// Device is the person's usual computer and Mobile their phone.
	Device, Mobile Device

	// Login is set for a test account, with what it demonstrates; the summary
	// lists it.
	Login string
}

// GuestRole is a role a person holds in an organization other than their own.
type GuestRole struct {
	Org  *Org
	Role string
}

// Name is the person's display name.
func (p *Person) Name() string { return p.First + " " + p.Last }

// Actor is the person as the author of an audited action.
func (p *Person) Actor() audit.Actor {
	id := p.ID
	return audit.Actor{UserID: &id, Type: "user", IP: p.Device.IP, UserAgent: p.Device.UserAgent}
}

// HasFactor reports whether the person enrolled factor.
func (p *Person) HasFactor(factor string) bool { return slices.Contains(p.MFA, factor) }

// Device is a browser or app a person signs in from.
type Device struct {
	Label     string // e.g. "Chrome on macOS"
	UserAgent string
	IP        string
	Country   string
}

// System is the actor for what the platform does by itself.
var System = audit.Actor{Type: "system"}
