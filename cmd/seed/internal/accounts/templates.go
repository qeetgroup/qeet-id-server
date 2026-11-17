package accounts

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
)

// template is an organization's customised email: which one, its content and
// how many days after sign-up it was written.
type template struct {
	key   string
	input email.EditorInput
	after int
}

func yes() *bool { b := true; return &b }

// customTemplates are the organizations that rewrote some of their emails;
// the rest send the built-in defaults.
var customTemplates = map[string][]template{
	"qeet": {
		{key: "invite", after: 6, input: email.EditorInput{
			Subject: "Join {{tenant_name}} on Qeet ID",
			Body: "Hi,\n\nYou've been invited to join {{tenant_name}} on Qeet ID, the single sign-on for every Qeet product.\n\n" +
				"Accept your invitation:\n{{invite_url}}\n\nThe link works once and expires in 14 days. If you weren't expecting it, you can ignore this email.\n\n— Qeet Group IT",
			Options: email.EditorOptions{
				Preheader: "Your invitation expires in 14 days.",
				HTML: `<p>Hi,</p><p>You've been invited to join <strong>{{tenant_name}}</strong> on Qeet ID, the single sign-on for every Qeet product.</p>` +
					`<p><a href="{{invite_url}}">Accept invitation</a></p><p>The link works once and expires in 14 days. If you weren't expecting it, you can ignore this email.</p><p>— Qeet Group IT</p>`,
				ShowLogo: yes(), Alignment: "left",
			},
		}},
		{key: "magic_link", after: 6, input: email.EditorInput{
			Subject: "Your Qeet sign-in link",
			Body:    "Use this link to sign in to Qeet:\n{{magic_url}}\n\nIt works once and expires in 30 minutes. If you didn't ask for it, ignore this email — nobody can sign in without the link.",
			Options: email.EditorOptions{Preheader: "Expires in 30 minutes.", ShowLogo: yes(), Alignment: "left"},
		}},
	},
	"northwind": {
		{key: "invite", after: 4, input: email.EditorInput{
			Subject: "You have been granted access to {{tenant_name}}",
			Body: "You have been granted access to {{tenant_name}} systems.\n\nAccept your invitation:\n{{invite_url}}\n\n" +
				"Access is for authorised business use only and is monitored. Do not forward this email.\n\nNorthwind Capital IT Service Desk · ext. 4357",
			Options: email.EditorOptions{Preheader: "Authorised business use only.", ShowLogo: yes(), Alignment: "center"},
		}},
		{key: "password_reset", after: 4, input: email.EditorInput{
			Subject: "Northwind Capital: reset your password",
			Body: "A password reset was requested for your Northwind Capital account.\n\nReset your password:\n{{reset_url}}\n\n" +
				"The link expires in 60 minutes. If you did not request it, call the IT Service Desk on ext. 4357 straight away. Northwind Capital will never ask for your password.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
		{key: "mfa_otp", after: 5, input: email.EditorInput{
			Subject: "Your Northwind Capital sign-in code",
			Body:    "Your one-time sign-in code is {{code}}. It expires in {{ttl}}.\n\nNorthwind Capital staff will never ask you for this code.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
	},
	"meridian": {
		{key: "invite", after: 15, input: email.EditorInput{
			Subject: "Your Meridian Health account is ready",
			Body: "Welcome to {{tenant_name}}.\n\nAccept your invitation to set up your account:\n{{invite_url}}\n\n" +
				"This message is intended for Meridian Health workforce members only. If you received it in error, delete it and notify the IT Service Desk at servicedesk@meridianhealth.us.",
			Options: email.EditorOptions{
				Preheader: "Set up your Meridian Health sign-in.",
				HTML: `<p>Welcome to <strong>{{tenant_name}}</strong>.</p><p><a href="{{invite_url}}">Set up your account</a></p>` +
					`<p><em>This message is intended for Meridian Health workforce members only. If you received it in error, delete it and notify the IT Service Desk.</em></p>`,
				ShowLogo: yes(), Alignment: "left",
			},
		}},
		{key: "verify_email", after: 15, input: email.EditorInput{
			Subject: "Verify your Meridian Health email address",
			Body:    "Your verification code is {{code}}. It expires in {{ttl}}.\n\nIf you didn't start this, contact the IT Service Desk.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "left"},
		}},
	},
	"lumen": {
		{key: "magic_link", after: 9, input: email.EditorInput{
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
		{key: "invite", after: 9, input: email.EditorInput{
			Subject: "Join {{tenant_name}}",
			Body:    "You're invited to {{tenant_name}}.\n\nAccept the invitation:\n{{invite_url}}\n\nSee you inside!\nThe Lumen Labs team",
			Options: email.EditorOptions{
				ShowLogo: yes(), Alignment: "center",
				Translations: map[string]email.LocalizedContent{
					"de": {
						Subject: "Einladung zu {{tenant_name}}",
						Body:    "Du wurdest zu {{tenant_name}} eingeladen.\n\nEinladung annehmen:\n{{invite_url}}\n\nBis gleich!\nDas Lumen-Labs-Team",
					},
				},
			},
		}},
	},
	"aster": {
		{key: "invite", after: 3, input: email.EditorInput{
			Subject: "{{tenant_name}} has invited you to the team",
			Body:    "Namaste!\n\nYou've been invited to {{tenant_name}}. Accept your invitation:\n{{invite_url}}\n\nNeed help? Write to care@asterretail.in.",
			Options: email.EditorOptions{ShowLogo: yes(), Alignment: "center"},
		}},
	},
}

// templates writes the organization's customised emails through the editor's
// own request; uncustomised ones keep the defaults.
func (s *seeder) templates(o *world.Org) {
	w := s.w
	for _, t := range customTemplates[o.Spec.Slug] {
		at := clamp(w, w.WorkHours(o.Spec.Since.Add(time.Duration(t.after)*24*time.Hour), o.Loc))
		actor := by(o, at)
		w.At(at, func() {
			s.api.do(o, actor, "", "PUT", "/tenants/"+o.ID.String()+"/email-templates/"+t.key, t.input)
		})
	}
}
