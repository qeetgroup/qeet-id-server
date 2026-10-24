package world

import (
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// OrgSpec describes a seeded organisation: who it is and how it uses Qeet ID.
// Every step reads it, so the organisations stay consistent across screens.
type OrgSpec struct {
	Slug, Name string
	Domain     string // email domain; never resolves, so nothing seeded reaches a real host
	Industry   string
	City       string // headquarters, e.g. "Mumbai"
	Country    string // ISO 3166-1 alpha-2
	TimeZone   string // IANA zone of the headquarters
	Region     string // data region
	Plan       string // free | starter | pro | enterprise
	Currency   string
	// Billing is the subscription's state: active, trialing, past_due or
	// canceled (a lapsed paid plan, now free).
	Billing  string
	Annual   bool
	Since    time.Time // when the organisation signed up
	Size     int       // people whose home is the organisation, owner included
	Locales  []Locale  // where its people come from, weighted by repetition
	Brand    Brand
	Features Features
	Depts    []Dept
	Story    string // one line on the organisation, for the summary
}

// Brand is an organisation's look on the hosted pages.
type Brand struct {
	Primary, Secondary, Background string // #rrggbb
}

// Features is how an organisation signs its people in and connects its
// systems. A feature its plan lacks is never set.
type Features struct {
	SSO         string   // SAML identity provider: okta, entra, google, onelogin, or "" for none
	SSOStatus   string   // active | draft
	SCIM        bool     // users provisioned from the identity provider
	LDAP        bool     // an on-premises directory
	Social      []string // tenant social providers: google, microsoft
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

// Org is a seeded organisation.
type Org struct {
	Spec   OrgSpec
	ID     uuid.UUID
	Tenant *tenant.Tenant
	Owner  *Person
	People []*Person // home members, owner first
	Guests []*Person // members whose home is another organisation
	Roles  map[string]uuid.UUID
	Groups map[string]uuid.UUID // department and team names
	// Loc is the headquarters' time zone.
	Loc *time.Location
}

// Has reports whether the organisation's plan includes a paid feature.
func (o *Org) Has(plan string) bool {
	rank := map[string]int{"free": 0, "starter": 1, "pro": 2, "enterprise": 3}
	effective := o.Spec.Plan
	if o.Spec.Billing == "canceled" {
		effective = "free"
	}
	return rank[effective] >= rank[plan]
}

// Members is everyone holding a role in the organisation: its people who
// are still members, then its guests.
func (o *Org) Members() []*Person {
	var out []*Person
	for _, p := range o.People {
		if p.Status != StatusDeleted {
			out = append(out, p)
		}
	}
	return append(out, o.Guests...)
}

// Active is the organisation's people who can sign in today.
func (o *Org) Active() []*Person {
	var out []*Person
	for _, p := range o.People {
		if p.Status == StatusActive {
			out = append(out, p)
		}
	}
	return out
}

// WithRole is the organisation's active people holding role.
func (o *Org) WithRole(role string) []*Person {
	var out []*Person
	for _, p := range o.Active() {
		if p.Role == role {
			out = append(out, p)
		}
	}
	return out
}

// Admins is the active people who can administer the organisation: its owner
// and every Admin.
func (o *Org) Admins() []*Person {
	var out []*Person
	for _, p := range o.Active() {
		if p.Role == RoleOwner || p.Role == RoleAdmin {
			out = append(out, p)
		}
	}
	return out
}

// InDept is the organisation's active people in dept.
func (o *Org) InDept(dept string) []*Person {
	var out []*Person
	for _, p := range o.Active() {
		if p.Department == dept {
			out = append(out, p)
		}
	}
	return out
}

// Person returns the organisation's person with email, or nil.
func (o *Org) Person(email string) *Person {
	for _, p := range o.People {
		if p.Email == email {
			return p
		}
	}
	return nil
}

// Role names every organisation on a paid plan has. Free plans allow no custom
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
	Loc        *time.Location
	Phone      string // E.164 from a fictional range; empty for some
	EmployeeID string
	Manager    *Person
	Role       string // role in the home organisation
	Joined     time.Time
	// Guest roles held in other organisations.
	GuestOf []GuestRole

	// Status is the account's state today. Since is when it left active.
	Status string
	Since  time.Time
	// Reason is the suspension reason (users.suspension_reason) and Source who
	// suspended it (manual, scim, ldap, policy).
	Reason, Source string
	Unverified     bool   // has never verified the email address
	Provisioned    string // how the account arrived: "" (invited or created), scim, ldap, saml
	ExternalID     string // the identity provider's id, for provisioned accounts

	// MFA lists the factors enrolled: totp, recovery, email, sms, push,
	// passkey. MFASince is when the first was.
	MFA      []string
	MFASince time.Time
	// Activity is the average number of sign-ins per working day.
	Activity float64
	// Device is the person's usual computer and Phone their phone, for
	// sessions and trusted devices.
	Device, Mobile Device

	// Login is set for a test account, with what it demonstrates; the summary
	// lists it.
	Login string
}

// GuestRole is a role a person holds in an organisation other than their own.
type GuestRole struct {
	Org   *Org
	Role  string
	Since time.Time
}

// Name is the person's display name.
func (p *Person) Name() string { return p.First + " " + p.Last }

// Actor is the person as the author of an audited action.
func (p *Person) Actor() audit.Actor {
	id := p.ID
	return audit.Actor{UserID: &id, Type: "user", IP: p.Device.IP, UserAgent: p.Device.UserAgent}
}

// HasFactor reports whether the person enrolled factor.
func (p *Person) HasFactor(factor string) bool {
	for _, f := range p.MFA {
		if f == factor {
			return true
		}
	}
	return false
}

// Device is a browser or app a person signs in from.
type Device struct {
	Kind      string // desktop | mobile | tablet
	Label     string // e.g. "Chrome on macOS"
	UserAgent string
	IP        string
	City      string
	Country   string
}

// System is the actor for what the platform does by itself.
var System = audit.Actor{Type: "system"}
