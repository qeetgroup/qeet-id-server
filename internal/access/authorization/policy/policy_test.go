package policy

import (
	"encoding/json"
	"testing"
	"time"
)

// TestDurationJSON: session bounds are written as duration strings the console
// edits, and read back from those or from the nanoseconds earlier responses
// carried.
func TestDurationJSON(t *testing.T) {
	for in, want := range map[time.Duration]string{
		720 * time.Hour:  `"720h"`,
		90 * time.Minute: `"90m"`,
		90 * time.Second: `"1m30s"`,
	} {
		got, err := json.Marshal(Duration(in))
		if err != nil || string(got) != want {
			t.Errorf("marshal %v = %s, %v; want %s", in, got, err, want)
		}
	}
	for raw, want := range map[string]time.Duration{
		`"720h"`:           720 * time.Hour,
		`"30m"`:            30 * time.Minute,
		`2592000000000000`: 720 * time.Hour,
	} {
		var d Duration
		if err := json.Unmarshal([]byte(raw), &d); err != nil || time.Duration(d) != want {
			t.Errorf("unmarshal %s = %v, %v; want %v", raw, time.Duration(d), err, want)
		}
	}
	var d Duration
	if err := json.Unmarshal([]byte(`"a month"`), &d); err == nil {
		t.Error("an unparseable duration was accepted")
	}
}

// TestNormalizeFillsDefaultsAndRefusesOutOfRange: bounds left out take the
// platform defaults, the idle timeout no longer than the maximum age; values
// out of range are named.
func TestNormalizeFillsDefaultsAndRefusesOutOfRange(t *testing.T) {
	r := &Repository{sessionMaxAge: 720 * time.Hour, sessionIdle: 24 * time.Hour}
	p := Policy{PasswordMinLength: 8, PasswordComplexity: "standard", MFAEnforcement: "optional", SessionMaxAge: Duration(2 * time.Hour)}
	if bad := r.normalize(&p); len(bad) != 0 {
		t.Fatalf("valid policy refused: %+v", bad)
	}
	if time.Duration(p.SessionIdleTimeout) != 2*time.Hour {
		t.Errorf("defaults not filled: idle %v", time.Duration(p.SessionIdleTimeout))
	}
	p = Policy{PasswordMinLength: 4, PasswordComplexity: "basic", MFAEnforcement: "disabled", MFAGraceDays: 91,
		SessionMaxAge: Duration(30 * time.Minute), SessionIdleTimeout: Duration(time.Hour)}
	got := map[string]bool{}
	for _, f := range r.normalize(&p) {
		got[f.Field] = true
	}
	for _, want := range []string{"session_max_age", "session_idle_timeout", "password_min_length", "password_complexity", "mfa_enforcement", "mfa_grace_days"} {
		if !got[want] {
			t.Errorf("%s out of range was not named (named: %v)", want, got)
		}
	}
}

// TestNormalizeStepUp: a policy that leaves the step-up window out gets five
// minutes and every factor type; a window outside 1m–60m, an unknown factor
// type or a repeated one is named.
func TestNormalizeStepUp(t *testing.T) {
	r := &Repository{sessionMaxAge: 720 * time.Hour, sessionIdle: 24 * time.Hour}
	base := func() Policy {
		return Policy{PasswordMinLength: 8, PasswordComplexity: "standard", MFAEnforcement: "optional"}
	}
	p := base()
	p.StepUpMethods = []string{}
	if bad := r.normalize(&p); len(bad) != 0 {
		t.Fatalf("valid policy refused: %+v", bad)
	}
	if time.Duration(p.StepUpWindow) != 5*time.Minute || p.StepUpMethods != nil {
		t.Errorf("defaults not filled: window %v methods %v", time.Duration(p.StepUpWindow), p.StepUpMethods)
	}
	for name, mutate := range map[string]func(*Policy){
		"window too short": func(p *Policy) { p.StepUpWindow = Duration(30 * time.Second) },
		"window too long":  func(p *Policy) { p.StepUpWindow = Duration(61 * time.Minute) },
		"unknown factor":   func(p *Policy) { p.StepUpMethods = []string{"totp", "sms"} },
		"repeated factor":  func(p *Policy) { p.StepUpMethods = []string{"webauthn", "webauthn"} },
	} {
		p := base()
		mutate(&p)
		named := false
		for _, f := range r.normalize(&p) {
			named = named || f.Field == "step_up_window" || f.Field == "step_up_methods"
		}
		if !named {
			t.Errorf("%s: not refused", name)
		}
	}
	p = base()
	p.StepUpWindow = Duration(time.Hour)
	p.StepUpMethods = []string{"webauthn", "totp"}
	if bad := r.normalize(&p); len(bad) != 0 {
		t.Errorf("a 60m window counting passkeys and the authenticator app was refused: %+v", bad)
	}
}
