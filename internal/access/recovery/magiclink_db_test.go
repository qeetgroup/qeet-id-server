//go:build integration

package recovery

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// magicLinksFor sets whether organization allows magic links, and for how long.
func magicLinksFor(t *testing.T, organization uuid.UUID, enabled bool, minutes int) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.auth_policy (organization_id, magic_link_enabled, magic_link_ttl_minutes) VALUES ($1, $2, $3)
		ON CONFLICT (organization_id) DO UPDATE SET magic_link_enabled = EXCLUDED.magic_link_enabled, magic_link_ttl_minutes = EXCLUDED.magic_link_ttl_minutes
	`, organization, enabled, minutes); err != nil {
		t.Fatal(err)
	}
}

// tokenIn returns the one-time token of the link in a magic-link message.
func tokenIn(t *testing.T, m notifier.Message) string {
	t.Helper()
	fields := strings.Fields(m.Body)
	u, err := url.Parse(fields[len(fields)-1])
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("no link in %q", m.Body)
	}
	return u.Query().Get("token")
}

// TestMagicLinkNamingAnotherOrganization checks that naming an organization the
// account doesn't belong to changes nothing about its link: the account's own
// organization decides whether one is sent, how long it lasts and whether it
// still works, and the named organization neither brands the message nor sees
// the request or its use. A member of the named organization still gets its
// branding, and both of its organizations see the request.
func TestMagicLinkNamingAnotherOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	svc.magicLinks = policies(t)
	home, named := dbtest.Organization(t), dbtest.Organization(t)
	magicLinksFor(t, home, true, 10)
	magicLinksFor(t, named, true, 1440)
	victim := dbtest.User(t, home, home)
	recorded := func(action string, organization uuid.UUID, a dbtest.Account) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND organization_id = $2 AND resource_id = $3`, action, organization, a.ID)
	}
	ask := func(a dbtest.Account) {
		t.Helper()
		if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: a.Email, OrganizationID: named}); err != nil {
			t.Fatalf("ask for a link naming the other organization: %v", err)
		}
		svc.deliveries.Wait()
	}

	ask(victim)
	msg := mail.Last(t)
	if msg.OrganizationID == named.String() {
		t.Error("the message is branded as an organization the account doesn't belong to")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.magic_links WHERE email = $1 AND organization_id IS NULL
		AND expires_at < NOW() + INTERVAL '11 minutes'`, victim.Email); n != 1 {
		t.Error("the link isn't held to the account's own organization's 10-minute lifetime")
	}
	if res, err := svc.ConsumeMagicLink(ctx, tokenIn(t, msg), audit.Actor{}); err != nil || res.UserID != victim.ID {
		t.Fatalf("use the link: %+v, %v", res, err)
	}
	for _, action := range []string{"auth.magic_link_requested", "auth.magic_link_consumed"} {
		if n, own := recorded(action, named, victim), recorded(action, home, victim); n != 0 || own != 1 {
			t.Errorf("%s recorded %d times by the named organization and %d by the account's own; want 0 and 1", action, n, own)
		}
	}

	ask(victim)
	earlier := tokenIn(t, mail.Last(t))
	magicLinksFor(t, home, false, 10)
	if _, err := svc.ConsumeMagicLink(ctx, earlier, audit.Actor{}); !errors.Is(err, errs.ErrAuthMethodDisabled) {
		t.Errorf("a link from before the account's organization switched them off: %v, want %v", err, errs.ErrAuthMethodDisabled)
	}
	sent := mail.Len()
	ask(victim)
	if mail.Len() != sent {
		t.Error("a link was sent though the account's own organization has magic links off")
	}

	guestHome := dbtest.Organization(t)
	guest := dbtest.User(t, guestHome, guestHome, named)
	ask(guest)
	if msg := mail.Last(t); msg.To != guest.Email || msg.OrganizationID != named.String() {
		t.Errorf("a member's message went to %s branded %q; want %s branded as the named organization", msg.To, msg.OrganizationID, guest.Email)
	}
	if n, own := recorded("auth.magic_link_requested", named, guest), recorded("auth.magic_link_requested", guestHome, guest); n != 1 || own != 1 {
		t.Errorf("a member's request recorded %d times by the named organization and %d by their own; want once each", n, own)
	}
}

// TestMagicLinkIntoUnprovedAccountEndsItsPassword checks that the first sign-in
// link an account uses proves its address as a reset does: the address is
// verified, and every credential and session set up before it ends, the
// password included, so whoever registered the address first keeps nothing.
func TestMagicLinkIntoUnprovedAccountEndsItsPassword(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	organization := dbtest.Organization(t)
	squatted := dbtest.User(t, organization, organization)
	giveCredentials(t, squatted, organization)
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2)`, squatted.ID, organization); err != nil {
		t.Fatal(err)
	}

	if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: squatted.Email}); err != nil {
		t.Fatal(err)
	}
	svc.deliveries.Wait()
	if res, err := svc.ConsumeMagicLink(ctx, tokenIn(t, mail.Last(t)), audit.Actor{}); err != nil || res.UserID != squatted.ID {
		t.Fatalf("use the link: %+v, %v", res, err)
	}
	if held := heldCredentials(t, squatted); len(held) != 0 {
		t.Errorf("after the link proved the address the account holds %v; want nothing set up before it", held)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, squatted.ID); n != 0 {
		t.Errorf("%d sessions from before the link stay open", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email_verified_at IS NOT NULL`, squatted.ID); n != 1 {
		t.Error("the address isn't marked verified after the link proved it")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.credentials_removed' AND resource_id = $1
		AND organization_id = $2 AND metadata->>'proof' = 'magic_link'`, squatted.ID, organization); n != 1 {
		t.Errorf("the removal was recorded %d times, want once", n)
	}

	// The address is proved now: a later link takes nothing away.
	dbtest.SetPassword(t, squatted.ID, "Kx7mQ2vLp9Wz-owner")
	if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: squatted.Email}); err != nil {
		t.Fatal(err)
	}
	svc.deliveries.Wait()
	if _, err := svc.ConsumeMagicLink(ctx, tokenIn(t, mail.Last(t)), audit.Actor{}); err != nil {
		t.Fatal(err)
	}
	if held := heldCredentials(t, squatted); held["password"] != 1 {
		t.Errorf("a link into a proved account left %v; want its password kept", held)
	}
}
