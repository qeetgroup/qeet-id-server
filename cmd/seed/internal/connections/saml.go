package connections

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// oidEmail is the emailAddress attribute vendors put in a certificate subject.
var oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// certificate is a self-signed X.509 certificate, PEM, valid from notBefore to
// notAfter, as an identity provider's signing certificate is.
func (f *fed) certificate(subject pkix.Name, notBefore, notAfter time.Time) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	f.w.Check(err, "generate a signing key")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(f.w.Rand.Int64()),
		Subject:               subject,
		NotBefore:             notBefore.UTC(),
		NotAfter:              notAfter.UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f.w.Check(err, "sign a certificate")
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// idp is one SAML identity provider connection, in its vendor's metadata
// format.
type idp struct {
	name, entityID, ssoURL, cert, emailAttr, nameAttr string
}

// orgLabel is the organisation's tenant name at a vendor, e.g. "northwindcapital".
func orgLabel(o *world.Org) string { return strings.SplitN(o.Spec.Domain, ".", 2)[0] }

// vendorIdP describes the organisation's connection to vendor, its signing
// certificate issued at issued.
func (f *fed) vendorIdP(o *world.Org, vendor string, issued time.Time) idp {
	label := orgLabel(o)
	switch vendor {
	case "okta":
		app := "exk" + f.token(alnum, 14) + f.token(digits, 3)
		return idp{
			name: "Okta", entityID: "http://www.okta.com/" + app,
			ssoURL: fmt.Sprintf("https://%s.okta.com/app/%s_qeetid_1/%s/sso/saml", label, label, app),
			cert: f.certificate(pkix.Name{Country: []string{"US"}, Province: []string{"California"}, Locality: []string{"San Francisco"},
				Organization: []string{"Okta"}, OrganizationalUnit: []string{"SSOProvider"}, CommonName: label,
				ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidEmail, Value: "info@okta.com"}}}, issued, issued.AddDate(10, 0, 0)),
			emailAttr: "email", nameAttr: "displayName",
		}
	case "entra":
		tid := f.uuid().String()
		return idp{
			name: "Microsoft Entra ID", entityID: "https://sts.windows.net/" + tid + "/",
			ssoURL:    "https://login.microsoftonline.com/" + tid + "/saml2",
			cert:      f.certificate(pkix.Name{CommonName: "Microsoft Azure Federated SSO Certificate"}, issued, issued.AddDate(3, 0, 0)),
			emailAttr: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			nameAttr:  "http://schemas.microsoft.com/identity/claims/displayname",
		}
	default:
		id := "C0" + f.token("0123456789abcdefghijklmnopqrstuvwxyz", 7)
		return idp{
			name: "Google Workspace", entityID: "https://accounts.google.com/o/saml2?idpid=" + id,
			ssoURL: "https://accounts.google.com/o/saml2/idp?idpid=" + id,
			cert: f.certificate(pkix.Name{Country: []string{"US"}, Province: []string{"California"}, Locality: []string{"Mountain View"},
				Organization: []string{"Google Inc."}, OrganizationalUnit: []string{"Google For Work"}, CommonName: "Google"},
				issued, issued.AddDate(5, 0, 0)),
			emailAttr: "email", nameAttr: "name",
		}
	}
}

// setup is when the organisation configured its identity provider and
// directories: SAML created and switched on, the SCIM token minted and the
// LDAP directory added and switched on. Each comes before the first account
// it brought in.
type setup struct {
	samlCreated, samlActive, scim, ldapCreated, ldapActive time.Time
}

// setupTimes places the organisation's set-up in its first days, before the
// first provisioned account arrived.
func (f *fed) setupTimes(o *world.Org) setup {
	if s, ok := f.setups[o.ID]; ok {
		return s
	}
	since := o.Spec.Since
	first := map[string]time.Time{}
	for _, p := range o.People[1:] {
		if p.Provisioned != "" && (first[p.Provisioned].IsZero() || p.Joined.Before(first[p.Provisioned])) {
			first[p.Provisioned] = p.Joined
		}
	}
	// within is def after since, give or take a few minutes, when that is
	// before the deadline; else the share-th part of the time up to it.
	within := func(def time.Duration, deadline time.Time, share float64) time.Time {
		t := since.Add(def + time.Duration(f.w.Rand.IntN(600))*time.Second)
		if deadline.IsZero() || t.Before(deadline.Add(-30*time.Second)) {
			return t
		}
		return since.Add(time.Duration(float64(deadline.Sub(since)-30*time.Second) * share))
	}
	s := setup{}
	switch {
	case len(first) > 0:
		deadline := first["scim"]
		if !first["ldap"].IsZero() && (deadline.IsZero() || first["ldap"].Before(deadline)) {
			deadline = first["ldap"]
		}
		s.samlCreated = within(25*time.Minute, deadline, 0.15)
		s.samlActive = within(90*time.Minute, deadline, 0.4)
		s.scim = within(26*time.Hour, first["scim"], 0.75)
		s.ldapCreated = within(40*time.Minute, first["ldap"], 0.5)
		s.ldapActive = within(2*time.Hour, first["ldap"], 0.85)
	case since.After(f.w.Days(14)):
		s.samlCreated = f.w.WorkHours(since.Add(3*24*time.Hour), o.Loc)
		s.samlActive = f.w.WorkHours(s.samlCreated.Add(24*time.Hour), o.Loc)
	default:
		s.samlCreated = f.w.WorkHours(since.Add(5*24*time.Hour), o.Loc)
		s.samlActive = f.w.WorkHours(s.samlCreated.Add(2*24*time.Hour), o.Loc)
	}
	f.setups[o.ID] = s
	return s
}

// sso connects the organisation to its SAML identity provider, active or a
// draft as its story says, and links the people who sign in through it.
func (f *fed) sso(o *world.Org) {
	vendor := o.Spec.Features.SSO
	if vendor == "" || !o.Has("pro") {
		return
	}
	w := f.w
	times := f.setupTimes(o)
	by := adminAt(o, times.samlCreated)
	issued := times.samlCreated.Add(-time.Duration(1+w.Rand.IntN(20)) * time.Hour)
	if vendor == "entra" {
		// Entra certificates last three years; this one was issued for the
		// enterprise app long ago and is due for renewal soon.
		issued = w.Now.AddDate(-3, 0, 27)
	}
	c := f.vendorIdP(o, vendor, issued)
	if o.Spec.Features.SSOStatus == "draft" {
		c.name += " (setup in progress)"
	}
	conn := f.samlConnection(o, by, times.samlCreated, c)

	if vendor == "entra" {
		// The rollout first ran against the identity provider's staging
		// tenant; that connection was switched off at go-live.
		staging := f.vendorIdP(o, vendor, times.samlCreated.AddDate(-1, 0, 0))
		staging.name += " (staging tenant)"
		sc := f.samlConnection(o, by, times.samlCreated.Add(-10*time.Minute), staging)
		f.samlStatus(o, by, times.samlCreated.Add(-4*time.Minute), sc, "active", nil)
		f.samlStatus(o, by, times.samlActive.Add(3*24*time.Hour), sc, "disabled", nil)
		w.Exec("staging sign-in", `UPDATE tenant.saml_connections SET last_login_at = $3 WHERE id = $1 AND tenant_id = $2`,
			sc, o.ID, times.samlActive.Add(-20*time.Minute))
	}
	if o.Spec.Features.SSOStatus != "active" {
		return
	}
	var idpInitiated *bool
	if vendor == "okta" {
		yes := true // people launch the app from their Okta dashboard
		idpInitiated = &yes
	}
	f.samlStatus(o, adminAt(o, times.samlActive), times.samlActive, conn, "active", idpInitiated)
	f.groupSync(o, conn, times.samlActive)
	f.breakGlass(o, times.samlActive)
	w.Exec("saml last sign-in", `UPDATE tenant.saml_connections SET last_login_at = $3 WHERE id = $1 AND tenant_id = $2`,
		conn, o.ID, f.ago(8*time.Minute, 58*time.Minute))

	// The people who sign in through it: everyone where the identity provider
	// provisions accounts, most people elsewhere. Directory accounts sign in
	// with LDAP instead.
	share := 0.65
	if o.Spec.Features.SCIM {
		share = 1
	}
	batch := &pgx.Batch{}
	for _, p := range o.Active() {
		if p.Provisioned == "ldap" || p.Unverified || !w.Chance(share) {
			continue
		}
		from := later(p.Joined.Add(10*time.Minute), times.samlActive.Add(5*time.Minute))
		if !from.Before(w.Now.Add(-time.Hour)) {
			continue
		}
		to := from.Add(5 * 24 * time.Hour)
		if to.After(w.Now.Add(-time.Hour)) {
			to = w.Now.Add(-time.Hour)
		}
		linked := f.workTime(from, to, p.Loc)
		batch.Queue(`INSERT INTO "user".external_identities (id, user_id, tenant_id, provider, connection_id, subject, email, metadata, linked_at)
			VALUES ($1, $2, $3, 'saml', $4, $5, $6, $7, $8)`, uuid.New(), p.ID, o.ID, conn, p.Email, p.Email,
			map[string]any{"connection": conn.String(), "idp": c.entityID}, linked)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "link SAML identities in "+o.Spec.Slug)
}

// samlConnection creates a draft connection at t, as by.
func (f *fed) samlConnection(o *world.Org, by *world.Person, t time.Time, c idp) uuid.UUID {
	w := f.w
	var id uuid.UUID
	w.At(t, func() {
		w.Tx("SAML connection "+c.name, func(tx pgx.Tx) error {
			conn, err := w.Deps.SAML.Service.Create(w.Ctx, tx, o.ID, saml.CreateInput{
				Name: c.name, IdpEntityID: c.entityID, IdpSSOURL: c.ssoURL, IdpCertificate: c.cert,
				EmailAttribute: c.emailAttr, NameAttribute: c.nameAttr, Status: "draft",
			})
			if err == nil {
				id = conn.ID
			}
			return err
		})
	})
	f.record(t, o, by, "saml.connection_created", "saml_connection", &id, map[string]any{"name": c.name, "idp": c.entityID})
	return id
}

// samlStatus changes a connection's status at t, as by.
func (f *fed) samlStatus(o *world.Org, by *world.Person, t time.Time, id uuid.UUID, status string, idpInitiated *bool) {
	w := f.w
	w.At(t, func() {
		w.Tx("SAML status", func(tx pgx.Tx) error {
			_, err := w.Deps.SAML.Service.Update(w.Ctx, tx, id, o.ID, saml.UpdateInput{Status: &status, AllowIdPInitiated: idpInitiated})
			return err
		})
	})
	f.record(t, o, by, "saml.connection_updated", "saml_connection", &id, map[string]any{"status": status})
}

// sp is an application that signs people in with Qeet ID as its SAML IdP.
type sp struct {
	name, entityID, acs, status, cert string
	access                            spec // who may sign in to it, when not everyone
}

// serviceProviders registers the SaaS applications an Enterprise organisation
// signs its people in to with Qeet ID as the identity provider, and records the
// assertions issued to the live ones.
func (f *fed) serviceProviders(o *world.Org) {
	if !o.Has("enterprise") || len(o.People) < 10 {
		return
	}
	w := f.w
	label := orgLabel(o)
	if o.Spec.Slug == "qeet" {
		label = "qeetgroup"
	}
	atlassian := f.uuid().String()
	awsRegion := map[string]string{"ap-south-1": "ap-south-1", "us-east-1": "us-east-1", "eu-west-1": "eu-west-1"}[o.Spec.Region]
	catalogue := map[string]sp{
		"atlassian": {name: "Atlassian Cloud", entityID: "https://auth.atlassian.com/saml/" + atlassian,
			acs: "https://auth.atlassian.com/login/callback?connection=saml-" + atlassian},
		"slack": {name: "Slack", entityID: "https://slack.com", acs: "https://" + label + ".slack.com/sso/saml"},
		"zoom":  {name: "Zoom", entityID: label + ".zoom.us", acs: "https://" + label + ".zoom.us/saml/SSO"},
		"aws": {name: "AWS IAM Identity Center",
			entityID: fmt.Sprintf("https://%s.signin.aws.amazon.com/platform/saml/d-%s", awsRegion, f.token("0123456789abcdef", 10)),
			acs:      fmt.Sprintf("https://%s.signin.aws.amazon.com/platform/saml/acs/%s", awsRegion, f.uuid())},
		"salesforce": {name: "Salesforce", entityID: "https://" + label + ".my.salesforce.com",
			acs: "https://" + label + ".my.salesforce.com?so=00D" + f.token(alnum, 12)},
	}
	// AWS is for the engineers who run production only, and Salesforce for the
	// people who talk to borrowers; everyone else's applications are open to all.
	plan := map[string][]struct {
		app, status string
		access      spec
	}{
		"qeet": {{app: "atlassian", status: "active"}, {app: "slack", status: "active"},
			{app: "aws", status: "draft", access: spec{groups: []string{"Site Reliability", "Qeet ID"}, users: []string{"aarav@qeet.in"}}}},
		"northwind": {{app: "salesforce", status: "active", access: spec{groups: []string{"Customer Service", "Collections"}, users: []string{"kavya.menon@northwindcapital.in"}}},
			{app: "zoom", status: "active"}, {app: "aws", status: "draft", access: spec{groups: []string{"Platform Engineering"}}}},
		"meridian": {{app: "zoom", status: "active"}, {app: "slack", status: "draft"}},
	}[o.Spec.Slug]
	start := f.setupTimes(o).samlActive.Add(3 * 24 * time.Hour)
	for i, item := range plan {
		s := catalogue[item.app]
		s.status, s.access = item.status, item.access
		at := start.Add(time.Duration(i*9)*24*time.Hour + time.Duration(w.Rand.IntN(5))*time.Hour)
		if item.status == "draft" {
			at = w.WorkHours(w.Days(float64(4+w.Rand.IntN(10))), o.Loc)
		}
		if item.app == "salesforce" {
			s.cert = f.certificate(pkix.Name{CommonName: "SelfSignedCert_" + at.Format("02Jan2006_150405"),
				OrganizationalUnit: []string{"00D" + f.token(alnum, 12)}, Organization: []string{"Salesforce.com"},
				Locality: []string{"San Francisco"}, Province: []string{"CA"}, Country: []string{"US"}}, at, at.AddDate(1, 0, 0))
		}
		f.serviceProvider(o, adminAt(o, at), at, s)
	}
}

// serviceProvider registers s at t as by, and for a live one the assertions
// issued to it since.
func (f *fed) serviceProvider(o *world.Org, by *world.Person, t time.Time, s sp) {
	w := f.w
	var id uuid.UUID
	w.At(t, func() {
		w.Tx("SAML service provider "+s.name, func(tx pgx.Tx) error {
			created, err := w.Deps.SAML.IdP.CreateSP(w.Ctx, tx, o.ID, saml.CreateSPInput{
				Name: s.name, EntityID: s.entityID, ACSURL: s.acs, Certificate: s.cert, Status: "draft",
				// The certificate is the one the app signs its requests with
				// (Salesforce's request signing certificate).
				RequireSignedRequests: s.cert != "",
			})
			if err == nil {
				id = created.ID
			}
			return err
		})
	})
	f.record(t, o, by, "saml.sp_created", "saml_service_provider", &id, map[string]any{"name": s.name, "entity_id": s.entityID})
	f.assign(o, by, t.Add(20*time.Minute), id, s.access)
	if s.status != "active" {
		return
	}
	on := t.Add(time.Duration(30+w.Rand.IntN(90)) * time.Minute)
	status := "active"
	w.At(on, func() {
		w.Tx("activate "+s.name, func(tx pgx.Tx) error {
			_, err := w.Deps.SAML.IdP.UpdateSP(w.Ctx, tx, id, o.ID, saml.UpdateSPInput{Status: &status})
			return err
		})
	})
	f.record(on, o, by, "saml.sp_updated", "saml_service_provider", &id, map[string]any{"status": status})

	// Assertions over the last month, from people who use it.
	people := o.Active()
	var last time.Time
	for range 8 + w.Rand.IntN(14) {
		p := world.Pick(w, people)
		from := later(w.Days(30), later(on, p.Joined).Add(time.Hour))
		if !from.Before(w.Now.Add(-30 * time.Minute)) {
			continue
		}
		at := f.workTime(from, w.Now.Add(-30*time.Minute), p.Loc)
		if at.After(w.Now.Add(-10 * time.Minute)) {
			continue
		}
		uid := p.ID
		w.Audit(at, audit.Event{TenantID: &o.ID, ActorUserID: &uid, ActorType: "user", Action: "saml.idp_assertion_issued",
			ResourceType: "saml_service_provider", ResourceID: &id, IP: p.Device.IP, UserAgent: p.Device.UserAgent,
			RequestID: f.requestID(), Metadata: map[string]any{"sp_entity_id": s.entityID}})
		if at.After(last) {
			last = at
		}
	}
	if !last.IsZero() {
		w.Exec("SP last sign-in", `UPDATE tenant.saml_service_providers SET last_login_at = $3 WHERE id = $1 AND tenant_id = $2`, id, o.ID, last)
	}
}
