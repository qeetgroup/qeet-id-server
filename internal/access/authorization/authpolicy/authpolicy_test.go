package authpolicy

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range protocol is SHA-1.
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestValidatePassword_MinLength(t *testing.T) {
	p := Policy{PasswordMinLength: 12}
	if err := ValidatePassword(p, "short"); err == nil {
		t.Error("expected min-length failure")
	}
	if err := ValidatePassword(p, "twelve-chars!"); err != nil {
		t.Errorf("12+ chars should pass: %v", err)
	}
}

func TestValidatePassword_Complexity(t *testing.T) {
	p := Policy{
		PasswordMinLength:        8,
		PasswordRequireUppercase: true,
		PasswordRequireNumber:    true,
		PasswordRequireSymbol:    true,
	}
	cases := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"all classes", "Abcdef1!", true},
		{"no uppercase", "abcdef1!", false},
		{"no number", "Abcdefg!", false},
		{"no symbol", "Abcdefg1", false},
		{"too short but complex", "Ab1!", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(p, c.pw)
			if c.ok && err != nil {
				t.Errorf("%q should pass, got %v", c.pw, err)
			}
			if !c.ok && err == nil {
				t.Errorf("%q should fail", c.pw)
			}
		})
	}
}

func TestValidatePassword_DefaultsAreLenient(t *testing.T) {
	// DefaultPolicy: min 8, no complexity required.
	if err := ValidatePassword(DefaultPolicy(), "password"); err != nil {
		t.Errorf("8-char password should pass default policy: %v", err)
	}
	if err := ValidatePassword(DefaultPolicy(), "short"); err == nil {
		t.Error("sub-8 should still fail under defaults")
	}
}

func TestIsSymbol(t *testing.T) {
	if isSymbol('a') || isSymbol('1') || isSymbol(' ') {
		t.Error("letters, digits, spaces are not symbols")
	}
	if !isSymbol('!') || !isSymbol('@') {
		t.Error("punctuation should be a symbol")
	}
}

// TestValidatePassword_TooShortNamesTheMinimum checks that a length refusal
// names the organisation's actual minimum.
func TestValidatePassword_TooShortNamesTheMinimum(t *testing.T) {
	err := ValidatePassword(Policy{PasswordMinLength: 14}, "Short-Pass-9!")
	e := errs.As(err)
	if e == nil || e.Code != errs.CodeAuthPolicyPasswordTooShort {
		t.Fatalf("err = %v, want %s", err, errs.CodeAuthPolicyPasswordTooShort)
	}
	if e.Message != "Your password must be at least 14 characters." {
		t.Errorf("message = %q, want it to name the 14-character minimum", e.Message)
	}
	if e.Metadata["min_length"] != 14 {
		t.Errorf("metadata = %v, want min_length 14", e.Metadata)
	}
}

// TestValidateForTenant_NoOrganisationUsesThePlatformBaseline checks that with
// no organisation the platform baseline applies without a database read, then
// the offline strength baseline, then the breach check.
func TestValidateForTenant_NoOrganisationUsesThePlatformBaseline(t *testing.T) {
	breached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte("Zq7#xLm2-breached")) // #nosec G401 -- HIBP protocol.
		digest := strings.ToUpper(hex.EncodeToString(sum[:]))
		if strings.HasSuffix(r.URL.Path, digest[:5]) {
			_, _ = w.Write([]byte(digest[5:] + ":3\r\n"))
		}
	}))
	defer breached.Close()
	s := &Service{} // no pool: uuid.Nil must not touch the database
	s.SetBreachChecker(hibp.New(breached.Client(), breached.URL, 1))

	for _, c := range []struct{ pw, code string }{
		{"Zq7#x", errs.CodeAuthPolicyPasswordTooShort}, // under the 8-character baseline
		{"password", errs.CodeAuthPasswordWeak},        // offline baseline: too common
		{"ada@example.com", errs.CodeAuthPasswordWeak}, // offline baseline: the email itself
		{"Zq7#xLm2-breached", errs.CodeAuthPolicyPasswordBreached},
		{"Zq7#xLm2", ""},
	} {
		err := s.ValidateForTenant(context.Background(), uuid.Nil, "ada@example.com", c.pw)
		got := ""
		if e := errs.As(err); e != nil {
			got = e.Code
		} else if err != nil {
			t.Fatalf("%q: unexpected error %v", c.pw, err)
		}
		if got != c.code {
			t.Errorf("%q: code = %q, want %q", c.pw, got, c.code)
		}
	}
}

func TestCheckLockout_BoundsAreInclusiveAndUnsetIsTheDefault(t *testing.T) {
	limits := DefaultLockoutLimits()
	n := func(v int) *int { return &v }
	if got := limits.CheckLockout(Policy{}); len(got) != 0 {
		t.Errorf("unset settings take the platform default, got %v", got)
	}
	ok := Policy{LockoutThreshold: n(3), LockoutWindowMinutes: n(1440), LockoutDurationMinutes: n(1)}
	if got := limits.CheckLockout(ok); len(got) != 0 {
		t.Errorf("settings on the bounds must be accepted, got %v", got)
	}
	bad := Policy{LockoutThreshold: n(21), LockoutWindowMinutes: n(0), LockoutDurationMinutes: n(1441)}
	got := limits.CheckLockout(bad)
	if len(got) != 3 {
		t.Fatalf("want all three settings refused, got %v", got)
	}
	for i, field := range []string{"lockout_threshold", "lockout_window_minutes", "lockout_duration_minutes"} {
		if got[i].Field != field || got[i].Code != "out_of_range" || !strings.Contains(got[i].Message, "between") {
			t.Errorf("refusal %d = %+v, want %s out_of_range naming the bounds", i, got[i], field)
		}
	}
}

func TestSignInLockout_NoTenantGetsThePlatformDefaults(t *testing.T) {
	s := &Service{lockout: DefaultLockoutLimits()} // no database: uuid.Nil must not read one
	got, err := s.SignInLockout(context.Background(), uuid.Nil)
	if err != nil || got != DefaultLockoutLimits().Defaults {
		t.Errorf("SignInLockout(no tenant) = %+v, %v; want the platform defaults", got, err)
	}
}
