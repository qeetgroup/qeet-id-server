// Package architecture_test enforces the repository's dependency-direction
// invariants as a build-time fitness function. It runs inside the normal
// `go test ./...` (and the CI backend job) with no extra tooling — it shells
// out to `go list` and inspects the import graph.
//
// Enforced today (see docs/ARCHITECTURE.md → "Enforced dependency rules"):
//
//	R1  platform/* (EXCEPT the platform/api/rest composition root) must NOT import
//	    domains/* or cmd/* — platform is infrastructure; it never depends on
//	    business domains or entrypoints. platform/api/rest is the one wiring
//	    exception (it mounts every domain handler and is imported only by cmd).
//
//	R2  domains/* must NOT import cmd/* or the platform/api/rest router — domain
//	    logic sits below wiring and entrypoints. (Importing the platform/api/rest
//	    sub-packages — middleware, paging, errs, codes — is fine; only the
//	    platform/api/rest router itself is off-limits.)
//
// Intentionally NOT enforced yet (would fail on current code — tighten later,
// e.g. with go-arch-lint once the graph is curated):
//
//	- cross-domain imports (domains/* -> other domains/*); today many domains
//	  legitimately depend on operations/audit, identity/users, etc.
//
// NOTE on caching: these tests read the import graph at runtime via `go list`,
// which Go's test cache cannot see — a plain `go test ./...` may serve a stale
// cached pass after you change another package. Run with `-count=1` (or
// `go clean -testcache`) to force re-evaluation. CI already runs
// `go test -race -count=1 ./...`, so the guard is always enforced there.
package architecture_test

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/qeetgroup/qeet-id-server"

type goPackage struct {
	ImportPath string
	Imports    []string
}

func loadPackages(t *testing.T) []goPackage {
	t.Helper()
	// `go list` resolves against the module regardless of the test's CWD.
	out, err := exec.Command("go", "list", "-json", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	var pkgs []goPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p goPackage
		switch err := dec.Decode(&p); err {
		case nil:
			pkgs = append(pkgs, p)
		case io.EOF:
			return pkgs
		default:
			t.Fatalf("decoding go list output: %v", err)
		}
	}
}

// rel strips the module prefix; returns "" for stdlib/third-party imports.
func rel(importPath string) string {
	switch {
	case importPath == module:
		return "."
	case strings.HasPrefix(importPath, module+"/"):
		return strings.TrimPrefix(importPath, module+"/")
	default:
		return ""
	}
}

func underCmd(p string) bool { return p == "cmd" || strings.HasPrefix(p, "cmd/") }

// underRouter matches only the wiring-root package (platform/api/rest), not its
// utility sub-packages (middleware, paging, errs, codes) which domains may use freely.
func underRouter(p string) bool {
	return p == "platform/api/rest"
}

// R1 — platform stays pure infrastructure.
func TestPlatformDoesNotImportDomainsOrCmd(t *testing.T) {
	for _, p := range loadPackages(t) {
		self := rel(p.ImportPath)
		if !strings.HasPrefix(self, "platform/") || underRouter(self) {
			continue // not platform-core (platform/api/rest is the allowed wiring exception)
		}
		for _, imp := range p.Imports {
			dep := rel(imp)
			switch {
			case strings.HasPrefix(dep, "domains/"):
				t.Errorf("R1 violation: %s imports %s — platform/* must not depend on domains/* (wiring belongs in platform/api/rest only)", self, dep)
			case underCmd(dep):
				t.Errorf("R1 violation: %s imports %s — platform/* must not depend on cmd/*", self, dep)
			}
		}
	}
}

// R2 — domains stay below wiring and entrypoints.
func TestDomainsDoNotImportCmdOrRouter(t *testing.T) {
	for _, p := range loadPackages(t) {
		self := rel(p.ImportPath)
		if !strings.HasPrefix(self, "domains/") {
			continue
		}
		for _, imp := range p.Imports {
			dep := rel(imp)
			switch {
			case underCmd(dep):
				t.Errorf("R2 violation: %s imports %s — domains/* must not depend on cmd/*", self, dep)
			case underRouter(dep):
				t.Errorf("R2 violation: %s imports %s — domains/* must not depend on the platform/api/rest router (use platform/api/rest/middleware utilities instead)", self, dep)
			}
		}
	}
}
