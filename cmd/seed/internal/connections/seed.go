// Package connections seeds how each organization connects to other systems:
// social sign-in providers, SAML and OpenID Connect identity providers with
// their group mappings and break-glass members, SAML service providers and
// who is assigned to them, LDAP directories, SCIM provisioning, OIDC
// applications and their grants, and enterprise-setup links.
package connections

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// fed is the step's state: what the summary needs.
type fed struct {
	w *world.World
	// hosted are the applications a tester signs in to, one per organization,
	// and device the one the device-flow test uses.
	hosted []app
	device *app
	// scim are the SCIM tokens minted, as summary lines.
	scim []string
	// portal is the live enterprise-setup link and whose it is; locked the
	// application left locked out.
	portal, locked string
}

// Seed connects every organization's identity providers and applications.
func Seed(w *world.World) {
	f := &fed{w: w}
	for _, o := range w.Orgs {
		f.social(o)
		f.sso(o)
		f.serviceProviders(o)
		f.oidcConnection(o)
		f.directories(o)
		f.applications(o)
		f.portalLinks(o)
	}
	f.notes()
}

// base is o's administration path.
func base(o *world.Org) string { return "/organizations/" + o.ID.String() }

// created is the id in a handler's answer.
type created struct {
	ID uuid.UUID `json:"id"`
}

// discovery is each OpenID Connect social provider's discovery document.
// GitHub, Facebook, X, Discord and Apple aren't OpenID Connect: Qeet ID calls
// each through its own adapter, so they have none.
var discovery = map[string]string{
	"google":    "https://accounts.google.com/.well-known/openid-configuration",
	"microsoft": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
}

// socialClient is a client ID and secret in the provider's own format: for
// Apple, a Services ID, team and key IDs and a real .p8 key, which Qeet ID signs
// its client secret with.
func socialClient(w *world.World, o *world.Org, provider string) social.CreateProviderInput {
	switch provider {
	case "google":
		return social.CreateProviderInput{ClientID: w.Token(world.Digits, 12) + "-" + w.Token("0123456789abcdefghijklmnopqrstuvwxyz", 32) + ".apps.googleusercontent.com",
			ClientSecret: "GOCSPX-" + w.Token(world.Alnum+"-_", 28)}
	case "github":
		return social.CreateProviderInput{ClientID: "Ov23li" + w.Token(world.Alnum, 14), ClientSecret: w.Token("0123456789abcdef", 40)}
	case "facebook":
		return social.CreateProviderInput{ClientID: "1" + w.Token(world.Digits, 15), ClientSecret: w.Token("0123456789abcdef", 32)}
	case "x":
		return social.CreateProviderInput{ClientID: w.Token(world.Alnum+"-_", 34), ClientSecret: w.Token(world.Alnum+"-_", 50)}
	case "discord":
		return social.CreateProviderInput{ClientID: "1" + w.Token(world.Digits, 18), ClientSecret: w.Token(world.Alnum+"-_", 32)}
	case "apple":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		w.Check(err, "Apple sign-in key")
		der, err := x509.MarshalPKCS8PrivateKey(key)
		w.Check(err, "encode Apple sign-in key")
		upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		return social.CreateProviderInput{ClientID: reverseDomain(o.Spec.Domain) + ".signin",
			ClientSecret: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
			AppleTeamID:  w.Token(upper, 10), AppleKeyID: w.Token(upper, 10)}
	default:
		return social.CreateProviderInput{ClientID: uuid.New().String(), ClientSecret: w.Token(world.Alnum, 3) + "8Q~" + w.Token(world.Alnum+"-_.~", 34)}
	}
}

// reverseDomain is domain in reverse-DNS order, as Apple Services IDs are.
func reverseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	slices.Reverse(parts)
	return strings.Join(parts, ".")
}

// social adds the organization's social sign-in providers through the
// social service, with client IDs in each vendor's format.
func (f *fed) social(o *world.Org) {
	w, by := f.w, o.Admin()
	for _, name := range o.Spec.Features.Social {
		in := socialClient(w, o, name)
		in.OrganizationID, in.Provider, in.DiscoveryURL = o.ID, name, discovery[name]
		in.Actor = audit.Actor{UserID: &by.ID, Type: "user", IP: by.Device.IP, UserAgent: by.Device.UserAgent}
		_, err := w.Deps.Social.Service.UpsertProvider(w.Ctx, in)
		w.Check(err, "social provider "+name+" for "+o.Spec.Slug)
	}
}

// certificate is a self-signed X.509 certificate, PEM, valid from notBefore to
// notAfter, as an identity provider's signing certificate is.
func certificate(w *world.World, subject pkix.Name, notBefore, notAfter time.Time) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	w.Check(err, "generate a signing key")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(w.Rand.Int64()), Subject: subject, NotBefore: notBefore.UTC(),
		NotAfter: notAfter.UTC(), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	w.Check(err, "sign a certificate")
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// oidEmail is the emailAddress attribute vendors put in a certificate subject.
var oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// idp is one SAML identity provider connection, in its vendor's metadata
// format.
type idp struct {
	name, entityID, ssoURL, cert, emailAttr, nameAttr string
}

// orgLabel is the organization's name at a vendor, e.g. "northwindcapital".
func orgLabel(o *world.Org) string { return strings.SplitN(o.Spec.Domain, ".", 2)[0] }

// vendorIdP describes the organization's connection to vendor, its signing
// certificate issued at issued.
func vendorIdP(w *world.World, o *world.Org, vendor string, issued time.Time) idp {
	label := orgLabel(o)
	switch vendor {
	case "okta":
		app := "exk" + w.Token(world.Alnum, 14) + w.Token(world.Digits, 3)
		return idp{
			name: "Okta", entityID: "http://www.okta.com/" + app,
			ssoURL: fmt.Sprintf("https://%s.okta.com/app/%s_qeetid_1/%s/sso/saml", label, label, app),
			cert: certificate(w, pkix.Name{Country: []string{"US"}, Province: []string{"California"}, Locality: []string{"San Francisco"},
				Organization: []string{"Okta"}, OrganizationalUnit: []string{"SSOProvider"}, CommonName: label,
				ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidEmail, Value: "info@okta.com"}}}, issued, issued.AddDate(10, 0, 0)),
			emailAttr: "email", nameAttr: "displayName",
		}
	case "entra":
		tid := uuid.New().String()
		return idp{
			name: "Microsoft Entra ID", entityID: "https://sts.windows.net/" + tid + "/",
			ssoURL:    "https://login.microsoftonline.com/" + tid + "/saml2",
			cert:      certificate(w, pkix.Name{CommonName: "Microsoft Azure Federated SSO Certificate"}, issued, issued.AddDate(3, 0, 0)),
			emailAttr: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			nameAttr:  "http://schemas.microsoft.com/identity/claims/displayname",
		}
	default:
		id := "C0" + w.Token("0123456789abcdefghijklmnopqrstuvwxyz", 7)
		return idp{
			name: "Google Workspace", entityID: "https://accounts.google.com/o/saml2?idpid=" + id,
			ssoURL: "https://accounts.google.com/o/saml2/idp?idpid=" + id,
			cert: certificate(w, pkix.Name{Country: []string{"US"}, Province: []string{"California"}, Locality: []string{"Mountain View"},
				Organization: []string{"Google Inc."}, OrganizationalUnit: []string{"Google For Work"}, CommonName: "Google"},
				issued, issued.AddDate(5, 0, 0)),
			emailAttr: "email", nameAttr: "name",
		}
	}
}

// groupMapping is the groups attribute an organization's identity provider
// sends, and which of its groups land in which of the organization's.
type groupMapping struct {
	attribute string
	groups    [][2]string // identity-provider group, the organization's group
}

// groupMappings are each organization's: Okta sends group names, Microsoft
// Entra ID the groups' object IDs. Only ordinary groups are mapped: one whose
// roles carry administration can't be handed out by the identity provider.
var groupMappings = map[string]groupMapping{
	"northwind": {attribute: "groups", groups: [][2]string{
		{"NW-Credit-Underwriting", "Credit Underwriting"}, {"NW-Collections", "Collections"},
		{"NW-Disbursement", "Disbursement"}, {"NW-Customer-Service", "Customer Service"},
	}},
	"meridian": {attribute: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", groups: [][2]string{
		{"3f1b6c2e-8d4a-4e71-9b0c-5a2f7d9e1c43", "Nursing"}, {"a8e02d71-4c9b-4f36-8e15-0b7d3c6a9f28", "Emergency Department"},
		{"5c7d9e1f-2a3b-4c5d-8e6f-7a8b9c0d1e2f", "Radiology"}, {"e1d2c3b4-a5f6-4789-9a0b-c1d2e3f4a5b6", "Billing & Coding"},
	}},
}

// sso connects the organization to its SAML identity provider through the
// console's requests, active or a draft as its story says. Where it is live,
// the identity provider's groups map to the organization's, and the owner and
// an administrator are break-glass members who may still use a password.
func (f *fed) sso(o *world.Org) {
	vendor := o.Spec.Features.SSO
	if vendor == "" || !o.Has("pro") {
		return
	}
	w, by := f.w, o.Admin()
	issued := time.Now().AddDate(0, -2, 0)
	if vendor == "entra" {
		issued = time.Now().AddDate(-3, 0, 27) // a three-year certificate, due for renewal soon
	}
	c := vendorIdP(w, o, vendor, issued)
	m := groupMappings[o.Spec.Slug]
	in := saml.CreateInput{Name: c.name, IdpEntityID: c.entityID, IdpSSOURL: c.ssoURL, IdpCertificate: c.cert,
		EmailAttribute: c.emailAttr, NameAttribute: c.nameAttr, GroupsAttribute: m.attribute, Status: "draft"}
	if o.Spec.Features.SSOStatus == "draft" {
		in.Name += " (setup in progress)"
	}
	var conn created
	w.API.Do(o, by, "POST", base(o)+"/saml", in, &conn)
	if vendor == "entra" {
		// The rollout first ran against the identity provider's staging organization,
		// switched off at go-live.
		staging := vendorIdP(w, o, vendor, issued.AddDate(1, 0, 0))
		var sc created
		w.API.Do(o, by, "POST", base(o)+"/saml", saml.CreateInput{Name: staging.name + " (staging organization)", IdpEntityID: staging.entityID,
			IdpSSOURL: staging.ssoURL, IdpCertificate: staging.cert, EmailAttribute: staging.emailAttr, NameAttribute: staging.nameAttr, Status: "draft"}, &sc)
		w.API.Do(o, by, "PATCH", base(o)+"/saml/"+sc.ID.String(), map[string]any{"status": "disabled"}, nil)
	}
	if o.Spec.Features.SSOStatus != "active" {
		return
	}
	// Okta's people launch the application from their Okta dashboard.
	w.API.Do(o, by, "PATCH", base(o)+"/saml/"+conn.ID.String(), map[string]any{"status": "active", "allow_idp_initiated": vendor == "okta"}, nil)
	for _, g := range m.groups {
		if gid, ok := o.Groups[g[1]]; ok {
			w.API.Do(o, by, "POST", base(o)+"/saml/"+conn.ID.String()+"/group-mappings", ssosync.MappingInput{IdPGroup: g[0], GroupID: gid}, nil)
		}
	}
	for _, p := range []*world.Person{o.Owner, by} {
		w.Check(w.Deps.DomainVerify.Service.SetBreakGlass(w.Ctx, o.ID, p.ID, true, o.Owner.Actor()), "break-glass "+p.Email)
	}
}

// sp is an application that signs people in with Qeet ID as its SAML IdP,
// and who may: every member, or only the groups and people named.
type sp struct {
	name, entityID, acs, status string
	groups, users               []string
	signed                      bool // it signs its requests (Salesforce)
}

// serviceProviders registers the SaaS applications an Enterprise organization
// signs its people in to with Qeet ID as the identity provider. AWS is for
// the engineers who run production only, Salesforce for the people who talk
// to borrowers; everyone else's applications are open to all.
func (f *fed) serviceProviders(o *world.Org) {
	if !o.Has("enterprise") || len(o.People) < 10 {
		return
	}
	w, by := f.w, o.Admin()
	label := orgLabel(o)
	if o.Spec.Slug == "qeet" {
		label = "qeetgroup"
	}
	atlassian := uuid.New().String()
	aws := fmt.Sprintf("https://%s.signin.aws.amazon.com/platform/saml/", o.Spec.Region)
	apps := map[string]sp{
		"atlassian":  {name: "Atlassian Cloud", entityID: "https://auth.atlassian.com/saml/" + atlassian, acs: "https://auth.atlassian.com/login/callback?connection=saml-" + atlassian},
		"slack":      {name: "Slack", entityID: "https://slack.com", acs: "https://" + label + ".slack.com/sso/saml"},
		"zoom":       {name: "Zoom", entityID: label + ".zoom.us", acs: "https://" + label + ".zoom.us/saml/SSO"},
		"aws":        {name: "AWS IAM Identity Center", entityID: aws + "d-" + w.Token(world.Hex, 10), acs: aws + "acs/" + uuid.New().String()},
		"salesforce": {name: "Salesforce", entityID: "https://" + label + ".my.salesforce.com", acs: "https://" + label + ".my.salesforce.com?so=00D" + w.Token(world.Alnum, 12), signed: true},
	}
	plan := map[string][]sp{
		"qeet": {{name: "atlassian", status: "active"}, {name: "slack", status: "active"},
			{name: "aws", status: "draft", groups: []string{"Site Reliability", "Qeet ID"}, users: []string{"aarav@qeet.in"}}},
		"northwind": {{name: "salesforce", status: "active", groups: []string{"Customer Service", "Collections"}, users: []string{"kavya.menon@northwindcapital.in"}},
			{name: "zoom", status: "active"}, {name: "aws", status: "draft", groups: []string{"Platform Engineering"}}},
		"meridian": {{name: "zoom", status: "active"}, {name: "slack", status: "draft"}},
	}[o.Spec.Slug]
	for _, item := range plan {
		s := apps[item.name]
		in := saml.CreateSPInput{Name: s.name, EntityID: s.entityID, ACSURL: s.acs, Status: "draft", RequireSignedRequests: s.signed,
			AssignmentRequired: len(item.groups)+len(item.users) > 0}
		if s.signed {
			in.Certificate = certificate(w, pkix.Name{CommonName: "SelfSignedCert_" + time.Now().Format("02Jan2006_150405"),
				OrganizationalUnit: []string{"00D" + w.Token(world.Alnum, 12)}, Organization: []string{"Salesforce.com"},
				Locality: []string{"San Francisco"}, Province: []string{"CA"}, Country: []string{"US"}}, time.Now(), time.Now().AddDate(1, 0, 0))
		}
		var c created
		w.API.Do(o, by, "POST", base(o)+"/saml-providers", in, &c)
		path := base(o) + "/saml-providers/" + c.ID.String()
		for _, g := range item.groups {
			w.API.Do(o, by, "POST", path+"/assignments/groups/"+o.Groups[g].String(), nil, nil)
		}
		for _, e := range item.users {
			w.API.Do(o, by, "POST", path+"/assignments/users/"+o.Person(e).ID.String(), nil, nil)
		}
		if item.status == "active" {
			w.API.Do(o, by, "PATCH", path, map[string]any{"status": "active"}, nil)
		}
	}
}

// oidcConnection gives Lumen Labs its OpenID Connect identity provider: its
// contract developers sign in from their agency's Microsoft Entra ID.
func (f *fed) oidcConnection(o *world.Org) {
	if o.Spec.Slug != "lumen" {
		return
	}
	w, by := f.w, o.Admin()
	organization, groups := "7d1c5b8e-2f4a-4b9d-a3c6-9e8f1d2b4a70", "groups"
	var c created
	w.API.Do(o, by, "POST", base(o)+"/oidc-connections", oidcsso.CreateInput{
		Name: "Brightwave Studios contractors (Microsoft Entra ID)", Issuer: "https://login.microsoftonline.com/" + organization + "/v2.0",
		ClientID: uuid.New().String(), ClientSecret: w.Token(world.Alnum, 3) + "8Q~" + w.Token(world.Alnum+"-_.~", 34),
		Scopes: []string{"openid", "email", "profile"}, AllowedIdPTenantIDs: []string{organization},
		ClaimMapping: &oidcsso.ClaimMappingInput{Groups: &groups}, Status: "draft",
	}, &c)
	w.API.Do(o, by, "PATCH", base(o)+"/oidc-connections/"+c.ID.String(), map[string]any{"status": "active"}, nil)
}

// mapping is an attribute mapping rule.
type mapping struct {
	source, target, kind, transform, pattern string
	enabled, required                        bool
}

// enterprise is the SCIM enterprise-user extension's attribute prefix.
const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// directories adds the organization's LDAP directory and SCIM provisioning
// (Enterprise features), with their attribute mappings and failure alerts.
func (f *fed) directories(o *world.Org) {
	feat := o.Spec.Features
	if (!feat.SCIM && !feat.LDAP) || !o.Has("enterprise") {
		return
	}
	w, by := f.w, o.Admin()
	if feat.LDAP {
		in := ldap.CreateInput{Name: "Staging Directory (test)", ServerURL: "ldaps://ldap.staging." + o.Spec.Domain + ":636",
			BindDN: "cn=svc-qeet-id,ou=service,dc=staging,dc=qeet,dc=in", BindPassword: w.Token(world.Alnum, 24),
			BaseDN: "ou=people,dc=staging,dc=qeet,dc=in", UserFilter: "(uid=%s)", EmailAttribute: "mail", NameAttribute: "cn", Status: "draft"}
		if o.Spec.Slug == "meridian" {
			in = ldap.CreateInput{Name: "Corporate Active Directory (corp.meridianhealth.us)", ServerURL: "ldaps://dc01.corp.meridianhealth.us:636",
				BindDN: "CN=svc-qeetid,OU=Service Accounts,OU=IT,DC=corp,DC=meridianhealth,DC=us", BindPassword: w.Token(world.Alnum+"!#%+", 20),
				BaseDN: "OU=Staff,DC=corp,DC=meridianhealth,DC=us", UserFilter: "(sAMAccountName=%s)", EmailAttribute: "mail",
				NameAttribute: "displayName", Status: "draft"}
		}
		var c created
		w.API.Do(o, by, "POST", base(o)+"/ldap", in, &c)
		if o.Spec.Slug == "meridian" {
			w.API.Do(o, by, "PATCH", base(o)+"/ldap/"+c.ID.String(), map[string]any{"status": "active"}, nil)
			f.mappings(o, c.ID.String(), []mapping{
				{"mail", "email", "string", "lowercase", "", true, true},
				{"displayName", "display_name", "string", "trim", "", true, false},
				{"givenName", "first_name", "string", "none", "", true, false},
				{"sn", "last_name", "string", "none", "", true, false},
				{"title", "title", "string", "trim", "", true, false},
				{"department", "department", "string", "trim", "", true, false},
				{"manager", "manager_id", "string", "extract", `^CN=([^,]+),`, true, false},
				{"memberOf", "groups", "array", "extract", `^CN=([^,]+),`, true, false},
			})
			w.API.Do(o, by, "POST", base(o)+"/directory/alerts", map[string]any{"name": "Active Directory outage", "connection_id": c.ID.String(),
				"threshold": 5, "enabled": true}, nil)
		}
	}
	if feat.SCIM {
		f.provision(o, by)
	}
	w.API.Do(o, by, "POST", base(o)+"/directory/alerts", map[string]any{"name": "Any directory failure (noisy)", "threshold": 10, "enabled": false}, nil)
}

// mappings saves conn's attribute mapping rules as the IT administrator did.
func (f *fed) mappings(o *world.Org, conn string, rules []mapping) {
	for _, m := range rules {
		f.w.API.Do(o, o.Admin(), "POST", base(o)+"/directory/connections/"+conn+"/mappings", map[string]any{"source_attribute": m.source,
			"target_field": m.target, "value_type": m.kind, "transform": m.transform, "pattern": m.pattern, "enabled": m.enabled, "required": m.required}, nil)
	}
}

// provision mints the token the identity provider pushes with, then has it
// push the organization's people over SCIM: each account the administrators
// made is adopted and tagged with its id there, and the people offboarded
// there are deactivated.
func (f *fed) provision(o *world.Org, by *world.Person) {
	w := f.w
	var minted struct {
		Token string `json:"token"`
	}
	vendor, agent := "Okta", "Okta SCIM Client 1.0.0"
	if o.Spec.Features.SSO == "entra" {
		vendor, agent = "Microsoft Entra ID", "Microsoft Azure AD SCIM Client"
	}
	w.API.Do(o, by, "POST", base(o)+"/scim/tokens", scim.TokenInput{Name: vendor + " provisioning"}, &minted)
	f.mappings(o, "scim:"+o.ID.String(), []mapping{
		{"userName", "email", "string", "lowercase", "", true, true},
		{"displayName", "display_name", "string", "trim", "", true, false},
		{"name.givenName", "first_name", "string", "trim", "", true, false},
		{"name.familyName", "last_name", "string", "trim", "", true, false},
		{"title", "title", "string", "trim", "", true, false},
		{enterprise + ":department", "department", "string", "none", "", true, false},
	})
	w.API.Do(o, by, "POST", base(o)+"/directory/alerts", map[string]any{"name": vendor + " provisioning failures",
		"connection_id": "scim:" + o.ID.String(), "threshold": 3, "enabled": true}, nil)
	for _, p := range o.People {
		if !p.Provisioned || p.Status == world.StatusDeleted {
			continue
		}
		var res created
		body := map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User", enterprise},
			"userName": p.Email, "externalId": p.ExternalID, "displayName": p.Name(), "title": p.Title, "active": true,
			"name":     map[string]any{"givenName": p.First, "familyName": p.Last},
			"emails":   []map[string]any{{"value": p.Email, "type": "work", "primary": true}},
			enterprise: map[string]any{"department": p.Department, "employeeNumber": p.EmployeeID},
		}
		w.API.SCIM(minted.Token, agent, "POST", "/Users", body, &res)
		if p.Status == world.StatusSuspended {
			w.API.SCIM(minted.Token, agent, "PATCH", "/Users/"+res.ID.String(), map[string]any{
				"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
				"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": false}}},
			}, nil)
		}
	}
	f.scim = append(f.scim, fmt.Sprintf("SCIM %-20s Authorization: Bearer %s  (%s/scim/v2/Users)", o.Spec.Name, minted.Token, w.BaseURL()))
}

// portalLinks mints the organization's enterprise-setup links: the one
// Vertex's Okta administrator has open now, one Northwind's used, one
// Meridian revoked, and Lumen's unused one.
func (f *fed) portalLinks(o *world.Org) {
	w, by := f.w, o.Admin()
	type minted struct {
		Token, URL string
		Link       created
	}
	link := func(caps []string, ttl time.Duration) minted {
		var out minted
		w.API.Do(o, by, "POST", base(o)+"/admin-portal/links", map[string]any{"capabilities": caps, "ttl_seconds": int(ttl.Seconds())}, &out)
		return out
	}
	switch o.Spec.Slug {
	case "vertex":
		f.portal = fmt.Sprintf("Enterprise-setup link (%s, SAML, 24h): %s", o.Spec.Name, link([]string{"saml"}, 24*time.Hour).URL)
	case "northwind":
		_, _, _, err := w.Deps.AdminPortal.Service.Exchange(w.Ctx, link([]string{"scim"}, 2*time.Hour).Token)
		w.Check(err, "open the enterprise-setup link")
	case "meridian":
		w.API.Do(o, by, "DELETE", base(o)+"/admin-portal/links/"+link([]string{"saml"}, 4*time.Hour).Link.ID.String(), nil, nil)
	case "lumen":
		link([]string{"saml"}, 24*time.Hour)
	}
}

// notes adds what testers need to the summary.
func (f *fed) notes() {
	w := f.w
	api, login := w.BaseURL(), strings.TrimRight(w.Cfg.LoginBaseURL, "/")
	section := fmt.Sprintf("Hosted sign-in, one app per organization (API %s, hosted pages %s)", api, login)
	w.Note(section, "Each URL signs in through the hosted pages and returns ?code=… to the app's loopback redirect (nothing listens:")
	w.Note(section, "copy the code from the address bar). PKCE verifier for every URL: %s", verifier)
	for _, h := range f.hosted {
		h.note(w, section, api)
	}
	if d := f.device; d != nil {
		s := "Device flow: " + d.org.Spec.Name + " · " + d.spec.name + " (" + d.clientID + ", public)"
		w.Note(s, "1. curl -s %s/v1/oauth/device_authorization -d client_id=%s -d 'scope=%s'", api, d.clientID, strings.Join(d.spec.scopes, " "))
		w.Note(s, "2. open %s/device?user_code=USER_CODE and sign in as %s", login, d.org.Owner.Email)
		w.Note(s, "3. curl -s %s/v1/oauth/token -d grant_type=%s -d client_id=%s -d device_code=DEVICE_CODE", api, deviceGrant, d.clientID)
	}
	const fedSection = "Federation"
	if f.portal != "" {
		w.Note(fedSection, "%s", f.portal)
	}
	for _, s := range f.scim {
		w.Note(fedSection, "%s", s)
	}
	if f.locked != "" {
		w.Note(fedSection, "Locked out after wrong secrets: %s — Applications → Auth failures", f.locked)
	}
}
