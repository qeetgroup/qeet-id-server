package activity

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRecordedFailuresAreErrors checks that every audit action recorded in
// internal/ that names a failure, lock or refusal is an error or critical, so
// the console never shows one as routine.
func TestRecordedFailuresAreErrors(t *testing.T) {
	actionRe := regexp.MustCompile(`(?:Action:\s*|\.(?:Platform)?Event\([^,()]*,\s*)"([a-z_]+\.[a-z_.]+)"`)
	failureRe := regexp.MustCompile(`(^|[._])(failed|locked|blocked|throttled|denied|rejected|refused)([._]|$)`)
	failures := map[string]bool{}
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
		for _, m := range actionRe.FindAllStringSubmatch(string(src), -1) {
			if failureRe.MatchString(m[1]) {
				failures[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !failures["auth.sign_in_failed"] || !failures["auth.account_locked"] {
		t.Fatalf("found %d failure actions, without the sign-in ones; the pattern is probably broken", len(failures))
	}
	for action := range failures {
		if sev := severityOf(action); sev != SeverityError && sev != SeverityCritical {
			t.Errorf("severityOf(%q) = %q, want error", action, sev)
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
