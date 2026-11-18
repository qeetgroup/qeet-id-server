package config

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// setRequiredEnv provides the variables envconfig requires, so Load errors in
// these tests can only come from the environment contract.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("SERVICE_ENV", EnvDev)
}

// TestLoad_RequiresServiceEnv checks that Load fails without SERVICE_ENV,
// naming it, rather than defaulting to dev with its gates off.
func TestLoad_RequiresServiceEnv(t *testing.T) {
	setRequiredEnv(t)
	if err := os.Unsetenv("SERVICE_ENV"); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SERVICE_ENV is not set") {
		t.Fatalf("Load without SERVICE_ENV: err = %v, want one naming SERVICE_ENV", err)
	}
}

func TestLoad_RejectsUnknownEnvironment(t *testing.T) {
	setRequiredEnv(t)
	for _, env := range []string{"staging", "production", "Prod", ""} {
		t.Setenv("SERVICE_ENV", env)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SERVICE_ENV") {
			t.Errorf("SERVICE_ENV=%q: want an environment error, got %v", env, err)
		}
	}
}

func TestLoad_ProfileRequiresLocal(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SERVICE_ENV", EnvDev)
	t.Setenv("SERVICE_PROFILE", "test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SERVICE_PROFILE") {
		t.Fatalf("Load must reject SERVICE_PROFILE outside SERVICE_ENV=local, got %v", err)
	}
	t.Setenv("SERVICE_ENV", EnvLocal)
	c, err := Load()
	if err != nil {
		t.Fatalf("local+test should load: %v", err)
	}
	if c.IsDev() || c.ServiceProfile != "test" {
		t.Errorf("got IsDev=%v profile=%q", c.IsDev(), c.ServiceProfile)
	}
}

// TestLoad_NeedsNoJWTSecret checks that the server starts without JWT_SECRET,
// which nothing signs or verifies with.
func TestLoad_NeedsNoJWTSecret(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_SECRET", "")
	if err := os.Unsetenv("JWT_SECRET"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err != nil {
		t.Fatalf("Load without JWT_SECRET: %v", err)
	}
}

// TestLoad_BreachedPasswordCheckOnByDefault checks that a deployment that
// doesn't set BREACHED_PASSWORD_CHECK checks passwords against known breaches,
// and that setting it false turns the check off.
func TestLoad_BreachedPasswordCheckOnByDefault(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("BREACHED_PASSWORD_CHECK", "")
	if err := os.Unsetenv("BREACHED_PASSWORD_CHECK"); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{EnvProd, EnvLocal} {
		t.Setenv("SERVICE_ENV", env)
		c, err := Load()
		if err != nil {
			t.Fatalf("SERVICE_ENV=%s: defaults should load: %v", env, err)
		}
		if !c.BreachedPasswordCheck {
			t.Errorf("SERVICE_ENV=%s: breached-password check is off by default, want on", env)
		}
	}
	t.Setenv("BREACHED_PASSWORD_CHECK", "false")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.BreachedPasswordCheck {
		t.Error("BREACHED_PASSWORD_CHECK=false left the check on")
	}
}

func TestLoad_SessionLifetimeDefaults(t *testing.T) {
	setRequiredEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("defaults should load: %v", err)
	}
	if c.SessionMaxAge != 720*time.Hour || c.SessionIdleTimeout != 24*time.Hour {
		t.Errorf("session defaults = %v / %v, want 720h / 24h", c.SessionMaxAge, c.SessionIdleTimeout)
	}
	if c.RefreshTokenReuseGrace != 30*time.Second {
		t.Errorf("refresh reuse grace default = %v, want 30s", c.RefreshTokenReuseGrace)
	}
	if c.ShutdownTimeout != 20*time.Second || c.ShutdownDrainDelay != 5*time.Second {
		t.Errorf("shutdown defaults = %v / %v, want 20s / 5s", c.ShutdownTimeout, c.ShutdownDrainDelay)
	}
}

func TestLoad_RejectsUnusableSessionLifetime(t *testing.T) {
	for name, env := range map[string][2]string{
		"maximum age under an hour":           {"SESSION_MAX_AGE", "30m"},
		"maximum age over a year":             {"SESSION_MAX_AGE", "9000h"},
		"idle timeout under 15 minutes":       {"SESSION_IDLE_TIMEOUT", "10m"},
		"idle timeout over the maximum age":   {"SESSION_IDLE_TIMEOUT", "721h"},
		"access tokens outliving idle bounds": {"ACCESS_TOKEN_TTL", "15m"},
		"a refresh reuse grace over a minute": {"REFRESH_TOKEN_REUSE_GRACE", "61s"},
		"a negative refresh reuse grace":      {"REFRESH_TOKEN_REUSE_GRACE", "-1s"},
		"a drain delay over 30 seconds":       {"SHUTDOWN_DRAIN_DELAY", "31s"},
		"a drain delay over half the stop":    {"SHUTDOWN_DRAIN_DELAY", "11s"},
		"a shutdown timeout under 5 seconds":  {"SHUTDOWN_TIMEOUT", "4s"},
		"a shutdown timeout over 2 minutes":   {"SHUTDOWN_TIMEOUT", "3m"},
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(env[0], env[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), env[0]) {
				t.Errorf("%s=%s: want a session lifetime error naming it, got %v", env[0], env[1], err)
			}
		})
	}
}

// envLine matches a variable in .env.example, set or commented out: KEY=… or # KEY=….
var envLine = regexp.MustCompile(`^#?\s*([A-Z][A-Z0-9_]*)=`)

// TestEnvExampleListsEveryVariable checks that .env.example names exactly the
// variables Config reads, so a new setting can't ship undocumented and a removed
// one can't linger.
func TestEnvExampleListsEveryVariable(t *testing.T) {
	want := map[string]bool{}
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		if key := typ.Field(i).Tag.Get("envconfig"); key != "" {
			want[key] = true
		}
	}
	if len(want) < 50 {
		t.Fatalf("Config has only %d envconfig tags; the test is probably broken", len(want))
	}

	f, err := os.Open(filepath.Join("..", "..", "..", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := envLine.FindStringSubmatch(sc.Text()); m != nil {
			got[m[1]] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	if missing := diff(want, got); len(missing) > 0 {
		t.Errorf(".env.example is missing %v: add each with its default and a one-line comment", missing)
	}
	if unknown := diff(got, want); len(unknown) > 0 {
		t.Errorf(".env.example lists %v, which Config doesn't read: remove them", unknown)
	}
}

// diff returns the keys of a that aren't in b, sorted.
func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
