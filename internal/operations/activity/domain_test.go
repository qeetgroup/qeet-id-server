package activity

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// recordedActions returns every audit action recorded in internal/: those named
// in an Event literal, an actor's Event or PlatformEvent, or the call of a
// record or audit helper.
func recordedActions(t *testing.T) map[string]bool {
	t.Helper()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:Action:\s*|\.(?:Platform)?Event\([^,()]*,\s*)"([a-z_]+\.[a-z_.]+)"`),
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

// TestEventsDescribeTheirDeviceAndPlace checks that an event names the
// browser, operating system and device type from its user agent, and its
// country, city and place from where its metadata says it came from.
func TestEventsDescribeTheirDeviceAndPlace(t *testing.T) {
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	ev := mapAuditRow(auditRow{ID: uuid.New(), Action: "auth.login_succeeded", UserAgent: &iphone,
		Metadata: []byte(`{"geo":{"country":"IN","city":"Pune"}}`)})
	if ev.Browser == nil || *ev.Browser != "Safari" || ev.OS == nil || *ev.OS != "iOS" || ev.Device == nil || *ev.Device != "mobile" {
		t.Errorf("an iPhone's event: browser %v, os %v, device %v", ev.Browser, ev.OS, ev.Device)
	}
	if ev.Country == nil || *ev.Country != "IN" || ev.City == nil || *ev.City != "Pune" || ev.Location == nil || *ev.Location != "Pune, IN" {
		t.Errorf("a placed event: country %v, city %v, location %v", ev.Country, ev.City, ev.Location)
	}
	curl := "curl/8.4.0"
	ev = mapAuditRow(auditRow{ID: uuid.New(), Action: "auth.login_succeeded", UserAgent: &curl})
	if ev.Browser == nil || *ev.Browser != "curl" || ev.OS != nil || ev.Device != nil || ev.Location != nil {
		t.Errorf("a curl event: browser %v, os %v, device %v, location %v", ev.Browser, ev.OS, ev.Device, ev.Location)
	}
}
