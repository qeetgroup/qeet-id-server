package accounts

import (
	"context"
	"errors"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/identity/group"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
)

// sender is the name an organization's email goes out with, and where replies go.
type sender struct{ name, replyTo string }

var senders = map[string]sender{
	"qeet":      {"Qeet Group", "support@qeet.in"},
	"northwind": {"Northwind Capital IT", "itservicedesk@northwindcapital.in"},
	"meridian":  {"Meridian Health IT Service Desk", "servicedesk@meridianhealth.us"},
	"lumen":     {"Lumen Labs", "support@lumenlabshq.dev"},
	"aster":     {"Aster Retail", "care@asterretail.in"},
	"vertex":    {"Vertex Freight IT", ""},
	"kestrel":   {"Kestrel Insurance Brokers", "operations@kestrelinsurance.in"},
}

// loginHosts are the custom hosted-login hostnames enterprise organizations
// set up. Neither resolves, so their DNS check stays pending.
var loginHosts = map[string]string{
	"northwind": "login.northwindcapital.in",
	"meridian":  "sso.meridianhealth.us",
}

// branding gives the organization, where its plan includes custom branding,
// its colours, background, email sender and custom sign-in hostname.
func (s *seeder) branding(o *world.Org) {
	snd, ok := senders[o.Spec.Slug]
	if !ok || !o.Has("starter") {
		return
	}
	settings := map[string]any{"background_color": o.Spec.Brand.Background}
	if snd.replyTo != "" {
		settings["email_reply_to"] = snd.replyTo
	}
	body := map[string]any{"primary_color": o.Spec.Brand.Primary, "secondary_color": o.Spec.Brand.Secondary,
		"email_from_name": snd.name, "settings": settings}
	if host, ok := loginHosts[o.Spec.Slug]; ok {
		body["custom_domain"] = host
	}
	s.w.API.Do(o, o.Admin(), "PUT", "/organizations/"+o.ID.String()+"/branding", body, nil)
}

// domainPlan is an email domain an organization claims and how far it got:
// verified, pending (nobody has checked) or attention (the check failed).
type domainPlan struct {
	name, state string
	sso, jit    bool
}

// domainPlans are each organization's claimed email domains.
var domainPlans = map[string][]domainPlan{
	"qeet":      {{"qeet.in", "verified", false, true}},
	"northwind": {{"northwindcapital.in", "verified", true, true}, {"northwind-capital.co.in", "verified", true, false}, {"nwcfinance.in", "attention", false, false}},
	"meridian":  {{"meridianhealth.us", "verified", true, true}, {"meridianhealthcare-us.org", "verified", true, false}, {"mhn-clinics.us", "pending", false, false}},
	"lumen":     {{"lumenlabshq.dev", "verified", true, true}, {"lumenlabs-cloud.io", "attention", false, false}},
	"aster":     {{"asterretail.in", "verified", false, false}, {"asterfashionhouse.in", "pending", false, false}},
	"vertex":    {{"vertexfreightco.us", "pending", false, false}},
	"kestrel":   {{"kestrelinsurance.in", "verified", false, false}},
}

// published answers the verification lookups for the TXT records the seeded
// organizations published; every other name is missing, as the domains don't
// resolve.
type published map[string]string

func (p published) LookupTXT(_ context.Context, name string) ([]string, error) {
	if token, ok := p[name]; ok {
		return []string{token}, nil
	}
	return nil, nil
}

// domains claims the organization's email domains through the domain
// service. A verified one published its TXT record and was checked; an
// attention one was checked without it. Custom domains are a paid feature.
func (s *seeder) domains(o *world.Org) {
	if !o.Has("starter") {
		return
	}
	svc, actor := s.w.Deps.DomainVerify.Service, o.Admin()
	for _, d := range domainPlans[o.Spec.Slug] {
		dom, err := svc.Add(s.w.Ctx, o.ID, d.name, actor.Actor())
		s.w.Check(err, "add domain "+d.name)
		switch d.state {
		case "verified":
			s.dns[dom.DNSRecordName] = dom.VerificationToken
			_, err = svc.Verify(s.w.Ctx, dom.ID, o.ID, actor.Actor())
			s.w.Check(err, "verify domain "+d.name)
			if d.sso || d.jit {
				_, err = svc.UpdateSettings(s.w.Ctx, dom.ID, o.ID, &d.sso, &d.jit, actor.Actor())
				s.w.Check(err, "domain settings "+d.name)
			}
		case "attention":
			if _, err := svc.Verify(s.w.Ctx, dom.ID, o.ID, actor.Actor()); err == nil {
				s.w.Check(errors.New("an unpublished record verified"), "check domain "+d.name)
			}
		}
	}
}

// security is an organization's security policy: how long
// sessions last and who must use a second factor.
type security struct {
	maxAge      time.Duration
	idle        time.Duration
	maxSessions int // 0: no limit
	stepUp      time.Duration
	methods     []string
}

// securityPolicies are the organizations that set their own security policy.
// The MFA requirement and grace period come from each one's Features.
var securityPolicies = map[string]security{
	"qeet":      {maxAge: 7 * 24 * time.Hour, idle: 24 * time.Hour, stepUp: 10 * time.Minute},
	"northwind": {maxAge: 12 * time.Hour, idle: 30 * time.Minute, maxSessions: 5, stepUp: 5 * time.Minute, methods: []string{"totp", "webauthn"}},
	"meridian":  {maxAge: 12 * time.Hour, idle: 15 * time.Minute, stepUp: 5 * time.Minute},
	"lumen":     {maxAge: 30 * 24 * time.Hour, idle: 7 * 24 * time.Hour, stepUp: 15 * time.Minute},
	"aster":     {maxAge: 14 * 24 * time.Hour, idle: 72 * time.Hour, stepUp: 5 * time.Minute},
	"kestrel":   {maxAge: 24 * time.Hour, idle: time.Hour, stepUp: 5 * time.Minute},
}

// signIn is how an organization's people may sign in, beyond its Features.
type signIn struct {
	minLength                 int
	upper, number, symbol     bool
	magicTTL                  int // minutes
	remember                  bool
	rememberDays              int
	lockThreshold, lockWindow int // failed attempts, minutes; 0: platform default
	lockDuration              int // minutes
}

// signInPolicies are the organizations that set their own sign-in policy.
var signInPolicies = map[string]signIn{
	"qeet":      {minLength: 12, upper: true, number: true, magicTTL: 30, remember: true, rememberDays: 30},
	"northwind": {minLength: 14, upper: true, number: true, symbol: true, lockThreshold: 3, lockWindow: 15, lockDuration: 30},
	"meridian":  {minLength: 12, number: true, symbol: true, lockThreshold: 5, lockWindow: 15, lockDuration: 20},
	"lumen":     {minLength: 10, magicTTL: 15, remember: true, rememberDays: 30},
	"aster":     {minLength: 8, magicTTL: 30, remember: true, rememberDays: 60},
	"vertex":    {minLength: 8},
	"kestrel":   {minLength: 10, number: true, remember: true, rememberDays: 7},
}

// retentionDays is how long each organization keeps deleted accounts before
// they are purged; 0 keeps them until someone purges them by hand.
var retentionDays = map[string]int{
	"qeet": 90, "northwind": 365, "meridian": 180, "lumen": 60, "kestrel": 90, "aster": 0, "cobalt": 0,
}

// policies sets the organization's sign-in, security and retention policies
// through the console's own requests. Northwind tightened its sessions after
// an audit, so its security policy has two versions.
func (s *seeder) policies(o *world.Org) {
	w, slug, f := s.w, o.Spec.Slug, o.Spec.Features
	path := "/organizations/" + o.ID.String()
	if si, ok := signInPolicies[slug]; ok {
		ttl := si.magicTTL
		if ttl == 0 {
			ttl = 60
		}
		p := authpolicy.Policy{
			PasswordEnabled: true, PasswordMinLength: si.minLength,
			PasswordRequireUppercase: si.upper, PasswordRequireNumber: si.number, PasswordRequireSymbol: si.symbol,
			MagicLinkEnabled: f.MagicLink, MagicLinkTTLMinutes: ttl,
			PasskeyEnabled: f.Passkeys, SelfRegistrationEnabled: f.SelfSignup,
			RememberDeviceEnabled: si.remember, RememberDeviceDays: si.rememberDays,
		}
		if si.lockThreshold > 0 {
			p.LockoutThreshold, p.LockoutWindowMinutes, p.LockoutDurationMinutes = &si.lockThreshold, &si.lockWindow, &si.lockDuration
		}
		w.API.Do(o, o.Admin(), "PUT", path+"/auth-policy", p, nil)
	}
	if sp, ok := securityPolicies[slug]; ok {
		p := authpolicy.SecurityPolicy{
			SessionMaxAge: authpolicy.Duration(sp.maxAge), SessionIdleTimeout: authpolicy.Duration(sp.idle),
			MFAEnforcement: f.MFA, MFAGraceDays: f.MFAGrace,
			StepUpWindow: authpolicy.Duration(sp.stepUp), StepUpMethods: sp.methods, Settings: map[string]any{},
		}
		if f.MFA == "admin_only" && p.MFAGraceDays == 0 {
			p.MFAGraceDays = 7 // Meridian gave its administrators a week to enrol
		}
		by := o.First(world.HasRole(world.RoleSecurity), world.HasRole(world.RoleITAdmin, world.RoleAdmin))
		if slug == "northwind" {
			first := p
			first.SessionIdleTimeout = authpolicy.Duration(time.Hour)
			w.API.Do(o, by, "PUT", path+"/policy", first, nil)
			p.MaxSessions = &sp.maxSessions
		}
		w.API.Do(o, by, "PUT", path+"/policy", p, nil)
	}
	if days, ok := retentionDays[slug]; ok {
		w.API.Do(o, o.Admin(), "PUT", path+"/retention", retention.Policy{DeletedUsersEnabled: days > 0, DeletedUsersDays: max(days, 30)}, nil)
	}
}

// template is an organization's customised email: which one and its content.
type template struct {
	key   string
	input email.EditorInput
}

func yes() *bool { b := true; return &b }

// customTemplates are the organizations that rewrote some of their emails;
// the rest send the built-in defaults.
var customTemplates = map[string][]template{
	"qeet": {
		{key: "invite", input: email.EditorInput{
			Subject: "Join {{organization_name}} on Qeet ID",
			Body: "Hi,\n\nYou've been invited to join {{organization_name}} on Qeet ID, the single sign-on for every Qeet product.\n\n" +
				"Accept your invitation:\n{{invite_url}}\n\nThe link works once and expires in 14 days. If you weren't expecting it, you can ignore this email.\n\n— Qeet Group IT",
			Options: email.EditorOptions{
				Preheader: "Your invitation expires in 14 days.",
				HTML: `<p>Hi,</p><p>You've been invited to join <strong>{{organization_name}}</strong> on Qeet ID, the single sign-on for every Qeet product.</p>` +
					`<p><a href="{{invite_url}}">Accept invitation</a></p><p>The link works once and expires in 14 days. If you weren't expecting it, you can ignore this email.</p><p>— Qeet Group IT</p>`,
				ShowLogo: yes(), Alignment: "left",
			},
		}},
		{key: "magic_link", input: email.EditorInput{
			Subject: "Your Qeet sign-in link",
			Body:    "Use this link to sign in to Qeet:\n{{magic_url}}\n\nIt works once and expires in 30 minutes. If you didn't ask for it, ignore this email — nobody can sign in without the link.",
			Options: email.EditorOptions{Preheader: "Expires in 30 minutes.", ShowLogo: yes(), Alignment: "left"},
		}},
	},
	"northwind": {
		{key: "invite", input: email.EditorInput{
			Subject: "You have been granted access to {{organization_name}}",
			Body: "You have been granted access to {{organization_name}} systems.\n\nAccept your invitation:\n{{invite_url}}\n\n" +
				"Access is for authorised business use only and is monitored. Do not forward this email.\n\nNorthwind Capital IT Service Desk · ext. 4357",
			Options: email.EditorOptions{Preheader: "Authorised business use only.", ShowLogo: yes(), Alignment: "center"},
		}},
		{key: "password_reset", input: email.EditorInput{
			Subject: "Northwind Capital: reset your password",
			Body: "A password reset was requested for your Northwind Capital account.\n\nReset your password:\n{{reset_url}}\n\n" +
				"The link expires in 60 minutes. If you did not request it, call the IT Service Desk on ext. 4357 straight away. Northwind Capital will never ask for your password.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
		{key: "mfa_otp", input: email.EditorInput{
			Subject: "Your Northwind Capital sign-in code",
			Body:    "Your one-time sign-in code is {{code}}. It expires in {{ttl}}.\n\nNorthwind Capital staff will never ask you for this code.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
	},
	"meridian": {
		{key: "invite", input: email.EditorInput{
			Subject: "Your Meridian Health account is ready",
			Body: "Welcome to {{organization_name}}.\n\nAccept your invitation to set up your account:\n{{invite_url}}\n\n" +
				"This message is intended for Meridian Health workforce members only. If you received it in error, delete it and notify the IT Service Desk at servicedesk@meridianhealth.us.",
			Options: email.EditorOptions{
				Preheader: "Set up your Meridian Health sign-in.",
				HTML: `<p>Welcome to <strong>{{organization_name}}</strong>.</p><p><a href="{{invite_url}}">Set up your account</a></p>` +
					`<p><em>This message is intended for Meridian Health workforce members only. If you received it in error, delete it and notify the IT Service Desk.</em></p>`,
				ShowLogo: yes(), Alignment: "left",
			},
		}},
		{key: "verify_email", input: email.EditorInput{
			Subject: "Verify your Meridian Health email address",
			Body:    "Your verification code is {{code}}. It expires in {{ttl}}.\n\nIf you didn't start this, contact the IT Service Desk.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "left"},
		}},
	},
	"lumen": {
		{key: "magic_link", input: email.EditorInput{
			Subject: "Your Lumen Labs sign-in link",
			Body:    "Click to sign in to Lumen Labs:\n{{magic_url}}\n\nThe link works once and expires in 15 minutes.",
			Options: email.EditorOptions{
				Preheader: "Expires in 15 minutes.", ShowLogo: yes(), Alignment: "center",
				Translations: map[string]email.LocalizedContent{
					"de": {
						Subject: "Dein Anmeldelink für Lumen Labs",
						Body:    "Klicke hier, um dich bei Lumen Labs anzumelden:\n{{magic_url}}\n\nDer Link funktioniert einmal und läuft in 15 Minuten ab.",
					},
				},
			},
		}},
		{key: "invite", input: email.EditorInput{
			Subject: "Join {{organization_name}}",
			Body:    "You're invited to {{organization_name}}.\n\nAccept the invitation:\n{{invite_url}}\n\nSee you inside!\nThe Lumen Labs team",
			Options: email.EditorOptions{
				ShowLogo: yes(), Alignment: "center",
				Translations: map[string]email.LocalizedContent{
					"de": {
						Subject: "Einladung zu {{organization_name}}",
						Body:    "Du wurdest zu {{organization_name}} eingeladen.\n\nEinladung annehmen:\n{{invite_url}}\n\nBis gleich!\nDas Lumen-Labs-Team",
					},
				},
			},
		}},
	},
	"aster": {
		{key: "invite", input: email.EditorInput{
			Subject: "{{organization_name}} has invited you to the team",
			Body:    "Namaste!\n\nYou've been invited to {{organization_name}}. Accept your invitation:\n{{invite_url}}\n\nNeed help? Write to care@asterretail.in.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
	},
}

// templates writes the organization's customised emails through the editor's
// own request; the rest keep the defaults.
func (s *seeder) templates(o *world.Org) {
	for _, t := range customTemplates[o.Spec.Slug] {
		s.w.API.Do(o, o.Admin(), "PUT", "/organizations/"+o.ID.String()+"/email-templates/"+t.key, t.input, nil)
	}
}

// groupRoles are roles granted to a whole team: everyone in the group holds
// the role's permissions on top of their own. None widens a test account's
// console beyond what its summary line promises.
var groupRoles = map[string][][2]string{
	"qeet":      {{"Governance, Risk & Compliance", world.RoleAuditor}},
	"northwind": {{"IT Operations", world.RoleITAdmin}, {"Internal Audit", world.RoleAuditor}},
	"meridian":  {{"Service Desk", world.RoleHelpdesk}, {"HIPAA Privacy", world.RoleAuditor}},
	"vertex":    {{"IT Support", world.RoleITAdmin}},
}

// groupTemplates are the group trees organizations saved to stamp out again.
var groupTemplates = map[string][]group.TemplateInput{
	"qeet": {{
		Name: "Product squad", Description: "A cross-functional squad: engineers, design and product",
		Nodes: []group.TemplateNode{{Name: "Squad", Description: "Everyone in the squad", Children: []group.TemplateNode{
			{Name: "Squad Engineering", Description: "Backend and frontend engineers"},
			{Name: "Squad Design", Description: "Product and UX design"},
			{Name: "Squad Product", Description: "Product manager and analyst"},
		}}},
	}},
	"northwind": {
		{
			Name: "Branch office", Description: "Groups for a new lending branch",
			Nodes: []group.TemplateNode{{Name: "Branch", Description: "Everyone at the branch", Children: []group.TemplateNode{
				{Name: "Branch Operations", Description: "Disbursement and customer service"},
				{Name: "Branch Credit", Description: "Credit underwriting"},
				{Name: "Branch Collections", Description: "Collections officers"},
			}}},
		},
		{
			Name: "Audit engagement", Description: "Time-boxed access for an external audit",
			Nodes: []group.TemplateNode{{Name: "Audit engagement", Description: "External auditors on an engagement", Children: []group.TemplateNode{
				{Name: "Audit engagement — fieldwork", Description: "Read-only access during fieldwork"},
			}}},
		},
	},
	"meridian": {{
		Name: "Hospital unit", Description: "Groups for a new clinical unit",
		Nodes: []group.TemplateNode{{Name: "Unit", Description: "Everyone on the unit", Children: []group.TemplateNode{
			{Name: "Unit Nursing", Description: "Registered and charge nurses"},
			{Name: "Unit Physicians", Description: "Attending physicians"},
			{Name: "Unit Clerks", Description: "Unit secretaries and patient access"},
		}}},
	}},
}

// groups grants roles to teams and saves group templates.
func (s *seeder) groups(o *world.Org) {
	w, actor := s.w, o.Admin()
	for _, gr := range groupRoles[o.Spec.Slug] {
		gid, ok := o.Groups[gr[0]]
		rid, has := o.Roles[gr[1]]
		if ok && has {
			w.Check(w.Deps.RBAC.Service.AssignRoleToGroup(w.Ctx, gid, o.ID, rid, &actor.ID, actor.Actor()), "group role "+gr[0])
		}
	}
	for _, t := range groupTemplates[o.Spec.Slug] {
		_, err := w.Deps.Group.Service.CreateTemplate(w.Ctx, o.ID, t, actor.Actor())
		w.Check(err, "group template "+t.Name)
	}
}
