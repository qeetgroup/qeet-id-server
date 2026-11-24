package activity

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// recordedActions returns every audit action recorded in internal/: those named
// in an Event literal, an actor's Event, EventIn or PlatformEvent, or the call
// of a record or audit helper.
func recordedActions(t *testing.T) map[string]bool {
	t.Helper()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:Action:\s*|\.(?:Platform)?Event(?:In)?\((?:[^,()]|\([^()]*\))*,\s*)"([a-z_]+\.[a-z_.]+)"`),
		regexp.MustCompile(`(?:[Rr]ecord|[Aa]udit)\w*\([^)]*?"([a-z_]+\.[a-z_.]+)"`),
	}
	actions := map[string]bool{}
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "dbgen" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				actions[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"auth.sign_in_failed", "auth.account_locked", "credential.issued", "ldap.connection_created"} {
		if !actions[want] {
			t.Fatalf("found %d recorded actions, without %s; the patterns are probably broken", len(actions), want)
		}
	}
	return actions
}

// TestRecordedFailuresAreErrors checks that every audit action recorded in
// internal/ that names a failure, lock or refusal is an error or critical, so
// the console never shows one as routine.
func TestRecordedFailuresAreErrors(t *testing.T) {
	failureRe := regexp.MustCompile(`(^|[._])(failed|locked|blocked|throttled|denied|rejected|refused)([._]|$)`)
	for action := range recordedActions(t) {
		if !failureRe.MatchString(action) {
			continue
		}
		if sev := severityOf(action); sev != SeverityError && sev != SeverityCritical {
			t.Errorf("severityOf(%q) = %q, want error", action, sev)
		}
	}
}

// TestEveryRecordedActionHasACategory checks that every audit action recorded
// in internal/ matches an entry of categoryPrefixes, so none is filed under
// system, and left out of its category's filter, for want of one.
func TestEveryRecordedActionHasACategory(t *testing.T) {
	for action := range recordedActions(t) {
		if !slices.ContainsFunc(categoryPrefixes, func(rule struct{ prefix, category string }) bool {
			return strings.HasPrefix(action, rule.prefix)
		}) {
			t.Errorf("%q matches no entry of categoryPrefixes; add its prefix with the category the console should file it under", action)
		}
	}
}

// TestCategoryOfRecordedActions checks the category of recorded actions whose
// prefix differs from a neighbour's only by a plural or an underscore.
func TestCategoryOfRecordedActions(t *testing.T) {
	cases := map[string]string{
		"credential.issued":       CategoryDeveloper,
		"credential.revoked":      CategoryDeveloper,
		"ip_rules.rule_added":     CategorySecurity,
		"social_provider.updated": CategoryAuthentication,
		"auth_policy.updated":     CategoryAuthentication,
		"abac_policy.created":     CategoryAuthorization,
		"email_template.updated":  CategoryDirectory,
		"billing.plan_changed":    CategorySystem,
		"gdpr.erasure_requested":  CategorySecurity,
		"invite.accepted":         CategoryDirectory,
	}
	for action, want := range cases {
		if got := categoryOf(action); got != want {
			t.Errorf("categoryOf(%q) = %q, want %q", action, got, want)
		}
	}
}

// TestSeverityOfRecordedActions checks the severity of recorded actions whose
// words are joined by underscores.
func TestSeverityOfRecordedActions(t *testing.T) {
	cases := map[string]string{
		"auth.sign_in_failed":                SeverityError,
		"auth.sign_in_refused_session_limit": SeverityError,
		"oidc.client_locked_out":             SeverityError,
		"auth.token_reuse_detected":          SeverityCritical,
		"oidc.authorization_code_reused":     SeverityCritical,
		"oidc.client_secret_rotated":         SeverityWarning,
		"session.admin_revoked_all":          SeverityWarning,
		"webhook.subscription_disabled":      SeverityWarning,
		"auth.login_succeeded":               SeveritySuccess,
		"mfa.totp_enrolled":                  SeveritySuccess,
		"auth.mfa_challenged":                SeverityInfo,
	}
	for action, want := range cases {
		if got := severityOf(action); got != want {
			t.Errorf("severityOf(%q) = %q, want %q", action, got, want)
		}
	}
}

// TestMapOutboxEventOrganizationID checks that mapOutboxEvent takes OrganizationID from its
// argument, not from the payload.
func TestMapOutboxEventOrganizationID(t *testing.T) {
	organizationID := uuid.New()
	otherID := uuid.New() // another UUID present in the payload — must not win
	payload := []byte(`{"organization_id":"` + otherID.String() + `","id":"00000000-0000-0000-0000-000000000001"}`)

	ev := mapOutboxEvent("user.events", "user.created", organizationID, payload)

	if ev.OrganizationID != organizationID {
		t.Errorf("OrganizationID = %v, want %v (must come from the caller-supplied organizationID)", ev.OrganizationID, organizationID)
	}
}

// TestCategoryOf checks categoryOf and severityOf against a sample of actions.
func TestCategoryOf(t *testing.T) {
	cases := []struct {
		action  string
		wantCat string
		wantSev string
	}{
		{"user.created", CategoryDirectory, SeveritySuccess},
		{"user.deleted", CategoryDirectory, SeverityWarning},
		{"auth.login.failed", CategoryAuthentication, SeverityError},
		{"auth.session.revoked_for_reuse", CategoryAuthentication, SeverityCritical},
		{"threat.anomaly_detected", CategorySecurity, SeverityCritical},
		{"rbac.role_assigned", CategoryAuthorization, SeverityInfo},
		{"group.member_added", CategoryDirectory, SeverityInfo},
		{"agent.created", CategoryDeveloper, SeveritySuccess},
		{"apikey.rotated", CategoryDeveloper, SeverityWarning},
		{"webhook.created", CategoryDeveloper, SeveritySuccess},
		{"system.shutdown", CategorySystem, SeverityInfo},
		{"mfa.enabled", CategoryAuthentication, SeveritySuccess},
		{"scim.user_provisioned", CategoryDirectory, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			if got := categoryOf(tc.action); got != tc.wantCat {
				t.Errorf("categoryOf(%q) = %q, want %q", tc.action, got, tc.wantCat)
			}
			if got := severityOf(tc.action); got != tc.wantSev {
				t.Errorf("severityOf(%q) = %q, want %q", tc.action, got, tc.wantSev)
			}
		})
	}
}

// stillReading lets every reader go on reading.
func stillReading(context.Context, *httpx.Principal) (bool, error) { return true, nil }

// testHandler is a Handler over pool and hub whose open streams' readers may
// always go on.
func testHandler(t testing.TB, pool *pgxpool.Pool, hub *Hub) *Handler {
	t.Helper()
	h, err := NewHandler(pool, hub, stillReading)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestNewHandlerNeedsTheStreamAccessCheck checks that the handler is not built
// without the check that ends a stream once its reader loses access, which
// would leave an open stream unchecked.
func TestNewHandlerNeedsTheStreamAccessCheck(t *testing.T) {
	if _, err := NewHandler(nil, NewHub(nil), nil); err == nil {
		t.Error("built without a stream access check")
	}
}
