//go:build integration

package email

import (
	"strings"
	"testing"

	"github.com/google/uuid"

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
		{"home organisation", home, anne.Email, "fr"},
		{"address in another case", home, strings.ToUpper(anne.Email), "fr"},
		{"member through a role", other, dirk.Email, "fr"},
		{"organisation the account isn't in", stranger, anne.Email, ""},
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
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.UpsertEditor(ctx, tx, organization, "magic_link", EditorInput{Subject: "Sign in", Body: "Use this link:\n{{magic_url}}", Options: EditorOptions{
			Translations: map[string]LocalizedContent{"fr": {Subject: "Connexion", Body: "Utilisez ce lien :\n{{magic_url}}"}},
		}}); err != nil {
			t.Fatalf("save template: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
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
