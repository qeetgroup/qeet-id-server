// Package architecture_test enforces the repository's dependency-direction
// invariants (see docs/ARCHITECTURE.md) as a build-time fitness function,
// shelling out to `go list` to inspect the import graph. R1: internal/platform/*
// imports no bounded context, cmd/*, or internal/bootstrap. R2: bounded contexts
// import neither cmd/* nor internal/bootstrap. Cross-context imports are not yet
// enforced.
//
// Caching gotcha: these tests read the import graph at runtime via `go list`,
// which the test cache cannot see — run with `-count=1` to force re-evaluation
// (CI already does `go test -race -count=1 ./...`).
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

// underBootstrap matches the composition root — the single wiring package
// allowed to import everything.
func underBootstrap(p string) bool {
	return p == "internal/bootstrap" || strings.HasPrefix(p, "internal/bootstrap/")
}

// contexts are the 5 bounded contexts. Business logic lives here; it sits below
// wiring (internal/bootstrap) and entrypoints (cmd/*).
var contexts = []string{
	"internal/access",
	"internal/identity",
	"internal/federation",
	"internal/developer",
	"internal/operations",
}

// underContext reports whether p is (or lives under) one of the 5 bounded contexts.
func underContext(p string) bool {
	for _, c := range contexts {
		if p == c || strings.HasPrefix(p, c+"/") {
			return true
		}
	}
	return false
}

// R1 — internal/platform stays pure infrastructure.
func TestPlatformDoesNotImportContextsOrCmd(t *testing.T) {
	for _, p := range loadPackages(t) {
		self := rel(p.ImportPath)
		if !strings.HasPrefix(self, "internal/platform/") {
			continue // only platform infrastructure is constrained by R1
		}
		for _, imp := range p.Imports {
			dep := rel(imp)
			switch {
			case underContext(dep):
				t.Errorf("R1 violation: %s imports %s — internal/platform/* must not depend on a bounded context (wiring belongs in internal/bootstrap only)", self, dep)
			case underCmd(dep):
				t.Errorf("R1 violation: %s imports %s — internal/platform/* must not depend on cmd/*", self, dep)
			case underBootstrap(dep):
				t.Errorf("R1 violation: %s imports %s — internal/platform/* must not depend on the composition root internal/bootstrap", self, dep)
			}
		}
	}
}

// R2 — bounded contexts stay below wiring and entrypoints.
func TestContextsDoNotImportCmdOrBootstrap(t *testing.T) {
	for _, p := range loadPackages(t) {
		self := rel(p.ImportPath)
		if !underContext(self) {
			continue
		}
		for _, imp := range p.Imports {
			dep := rel(imp)
			switch {
			case underCmd(dep):
				t.Errorf("R2 violation: %s imports %s — bounded contexts must not depend on cmd/*", self, dep)
			case underBootstrap(dep):
				t.Errorf("R2 violation: %s imports %s — bounded contexts must not depend on the composition root internal/bootstrap (import internal/platform/* utilities instead)", self, dep)
			}
		}
	}
}
