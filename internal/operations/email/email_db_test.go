//go:build integration

package email

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestRecipientLocaleStaysWithItsOrganization checks that an organization's
// email is rendered in the recipient's profile language when the account
// belongs to it, and that another organization's email to the same address
// neither reads that profile nor leaves its own default locale.
func TestRecipientLocaleStaysWithItsOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	service := NewService(pool)
	home, other, stranger := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
	anne := dbtest.User(t, home)
	dirk := dbtest.User(t, uuid.Nil, other)
	for _, id := range []uuid.UUID{anne.ID, dirk.ID} {
		if _, err := pool.Exec(ctx, `UPDATE account.users SET metadata = jsonb_build_object('locale', 'fr') WHERE id = $1`, id); err != nil {
			t.Fatalf("set locale: %v", err)
		}
	}

	for _, test := range []struct {
		name         string
		organization uuid.UUID
		address      string
		want         string
	}{
		{"home organization", home, anne.Email, "fr"},
		{"address in another case", home, strings.ToUpper(anne.Email), "fr"},
		{"member through a role", other, dirk.Email, "fr"},
		{"organization the account isn't in", stranger, anne.Email, ""},
		{"no account", home, "nobody@example.test", ""},
	} {
		got, err := service.RecipientLocale(ctx, test.organization, test.address)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got != test.want {
			t.Errorf("%s: locale = %q, want %q", test.name, got, test.want)
		}
	}

	for _, organization := range []uuid.UUID{home, stranger} {
		if _, err := service.UpsertEditor(ctx, organization, "magic_link", EditorInput{Subject: "Sign in", Body: "Use this link:\n{{magic_url}}", Options: EditorOptions{
			Translations: map[string]LocalizedContent{"fr": {Subject: "Connexion", Body: "Utilisez ce lien :\n{{magic_url}}"}},
		}}, audit.Actor{Type: "system"}); err != nil {
			t.Fatalf("save template: %v", err)
		}
	}
	mailbox := &dbtest.Mailbox{}
	sender := TemplateSender{Templates: service, Next: mailbox}
	for organization, want := range map[uuid.UUID]string{home: "Connexion", stranger: "Sign in"} {
		if err := sender.Send(ctx, notifier.Message{OrganizationID: organization.String(), Channel: "email", To: anne.Email, TemplateKey: "magic_link",
			TemplateVariables: map[string]string{"magic_url": "https://example.test/once"}, Subject: "Original", Body: "Original"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		if got := mailbox.Last(t).Subject; got != want {
			t.Errorf("subject = %q, want %q", got, want)
		}
	}
}

// TestEachTemplateIsSentCustomisedUntilReset checks that each template's saved
// version is sent until it is reset, and only for its organization.
func TestEachTemplateIsSentCustomisedUntilReset(t *testing.T) {
	ctx := dbtest.Context(t)
	service := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	actor := audit.Actor{Type: "system"}
	mailbox := &dbtest.Mailbox{}
	sender := TemplateSender{Templates: service, Next: mailbox}
	for _, test := range []struct {
		key       string
		custom    EditorInput
		variables map[string]string
		want      string // what the customised text shows of the message's values
	}{
		{"verify_email", EditorInput{Subject: "Confirm your Brightleaf address", Body: "Your Brightleaf code is {{code}}. It expires in {{ttl}}."},
			map[string]string{"code": "482913", "ttl": "10 minutes"}, "Your Brightleaf code is 482913. It expires in 10 minutes."},
		{"password_reset", EditorInput{Subject: "Reset your Brightleaf password", Body: "Choose a new password:\n{{reset_url}}"},
			map[string]string{"reset_url": "https://accounts.example.test/reset-password?token=once"}, "https://accounts.example.test/reset-password?token=once"},
		{"mfa_otp", EditorInput{Subject: "Your Brightleaf sign-in code", Body: "Your Brightleaf sign-in code is {{code}}. It expires in {{ttl}}."},
			map[string]string{"code": "771204", "ttl": "10 minutes"}, "Your Brightleaf sign-in code is 771204."},
		{"magic_link", EditorInput{Subject: "Sign in to Brightleaf", Body: "Use this link:\n{{magic_url}}"},
			map[string]string{"magic_url": "https://accounts.example.test/magic-link?token=once"}, "https://accounts.example.test/magic-link?token=once"},
		{"invite", EditorInput{Subject: "Join Brightleaf", Body: "Accept your invitation:\n{{invite_url}}"},
			map[string]string{"invite_url": "https://console.example.test/invite/accept?token=once"}, "https://console.example.test/invite/accept?token=once"},
	} {
		send := func(to uuid.UUID) notifier.Message {
			t.Helper()
			if err := sender.Send(ctx, notifier.Message{OrganizationID: to.String(), Channel: "email", To: "anne@example.test", TemplateKey: test.key,
				TemplateVariables: test.variables, Subject: "Platform subject", Body: "Platform body"}); err != nil {
				t.Fatalf("%s: send: %v", test.key, err)
			}
			return mailbox.Last(t)
		}
		if got := send(organization); got.Subject != "Platform subject" {
			t.Errorf("%s before it is customised: subject %q, want the platform's", test.key, got.Subject)
		}
		if _, err := service.UpsertEditor(ctx, organization, test.key, test.custom, actor); err != nil {
			t.Fatalf("%s: save: %v", test.key, err)
		}
		got := send(organization)
		if got.Subject != test.custom.Subject || !strings.Contains(got.Body, test.want) || !strings.Contains(got.HTML, test.custom.Subject) {
			t.Errorf("%s customised: subject %q body %q; want the organization's version showing %q", test.key, got.Subject, got.Body, test.want)
		}
		if got := send(other); got.Subject != "Platform subject" || got.Body != "Platform body" {
			t.Errorf("%s to another organization's member: %q, want the platform's", test.key, got.Subject)
		}
		if _, err := service.Reset(ctx, organization, test.key, actor); err != nil {
			t.Fatalf("%s: reset: %v", test.key, err)
		}
		if got := send(organization); got.Subject != "Platform subject" || got.Body != "Platform body" {
			t.Errorf("%s after the customisation is removed: subject %q body %q, want the platform's", test.key, got.Subject, got.Body)
		}
	}
}

func TestMain(m *testing.M) { dbtest.Main(m) }

// refuseAudit makes the organization's audit writes of action fail until t
// ends, as an audit store that is down would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, name := dbtest.Owner(t), "refuse_"+strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := owner.Exec(dbtest.Context(t), `
		CREATE FUNCTION pg_temp.`+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store down'; END $$;
		CREATE TRIGGER `+name+` BEFORE INSERT ON audit.events FOR EACH ROW
		WHEN (NEW.organization_id = '`+organization.String()+`' AND NEW.action = '`+action+`') EXECUTE FUNCTION pg_temp.`+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP FUNCTION pg_temp.`+name+`() CASCADE`) })
}

// events counts the organization's audit events of action.
func events(t *testing.T, organization uuid.UUID, action string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2`, organization, action)
}

// TestTemplateChangesCommitWithTheirAuditEvents checks that saving and
// resetting a template are each recorded in the transaction that makes them:
// undone when the event can't be written, and recorded once when it can.
func TestTemplateChangesCommitWithTheirAuditEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	actor := audit.Actor{Type: "system"}
	custom := func() bool {
		t.Helper()
		res, err := svc.Get(ctx, organization, "magic_link")
		if err != nil {
			t.Fatal(err)
		}
		return res.Custom
	}
	draft := EditorInput{Subject: "Sign in", Body: "Use this link:\n{{magic_url}}"}

	refuseAudit(t, organization, "email_template.updated")
	if _, err := svc.UpsertEditor(ctx, organization, "magic_link", draft, actor); err == nil {
		t.Fatal("save while its audit event can't be written: no error")
	}
	if custom() {
		t.Error("the template was saved without its audit event")
	}

	other := dbtest.Organization(t)
	if _, err := svc.UpsertEditor(ctx, other, "magic_link", draft, actor); err != nil {
		t.Fatal(err)
	}
	refuseAudit(t, other, "email_template.reset")
	if _, err := svc.Reset(ctx, other, "magic_link", actor); err == nil {
		t.Fatal("reset while its audit event can't be written: no error")
	}
	if res, err := svc.Get(ctx, other, "magic_link"); err != nil || !res.Custom {
		t.Errorf("template after a failed reset: %+v, %v; want it still customised", res, err)
	}
	if n := events(t, other, "email_template.updated"); n != 1 {
		t.Errorf("%d saves recorded, want 1", n)
	}
}
