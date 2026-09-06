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
	"sort"
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

// ── R3: cross-context coupling ───────────────────────────────────────────────
//
// R1/R2 above constrain the layering (platform below contexts, contexts below
// wiring) but say nothing about contexts importing each other. That gap let 37
// cross-context edges accumulate unnoticed. R3 closes it.
//
// A bounded context may import another context ONLY through a package named in
// sharedKernel. Everything else is a violation. Keeping the rule as an
// allowlist of *targets* (4 entries) rather than of edges (37) keeps it
// readable and still fails on any genuinely new coupling.
//
// Adding an entry here is an architecture decision, not a formality: it makes
// the target a de-facto shared dependency of the whole monolith. Prefer a
// consumer-declared interface satisfied by the composition root
// (internal/bootstrap) — that is how a context depends on another context's
// behaviour without depending on its types.
var sharedKernel = []string{
	// Audit is a cross-cutting write primitive: every context records security
	// events through audit.Record. It is a bounded context by location only —
	// see the note on TestCrossContextCycle below.
	"internal/operations/audit",
	// Token issuance. Federation (saml/oidc/social/ldap) and identity
	// (tenant/invitations) complete a login by minting a session here.
	"internal/access/authentication",
	// Permission checks for machine principals (agents, API keys, service
	// principals) live in developer/ but authorize against the access model.
	"internal/access/authorization/rbac",
	// The user aggregate, read by authentication and by SCIM provisioning.
	"internal/identity/users",
}

// contextOf returns the bounded context a package belongs to ("access",
// "identity", …), or "" for anything outside the five contexts.
func contextOf(p string) string {
	for _, c := range contexts {
		if p == c || strings.HasPrefix(p, c+"/") {
			return strings.TrimPrefix(c, "internal/")
		}
	}
	return ""
}

func inSharedKernel(dep string) bool {
	for _, k := range sharedKernel {
		if dep == k || strings.HasPrefix(dep, k+"/") {
			return true
		}
	}
	return false
}

// R3 — a bounded context reaches another context only via the shared kernel.
func TestCrossContextImportsGoThroughSharedKernel(t *testing.T) {
	for _, p := range loadPackages(t) {
		self := rel(p.ImportPath)
		selfCtx := contextOf(self)
		if selfCtx == "" {
			continue
		}
		for _, imp := range p.Imports {
			dep := rel(imp)
			depCtx := contextOf(dep)
			if depCtx == "" || depCtx == selfCtx || inSharedKernel(dep) {
				continue
			}
			t.Errorf("R3 violation: %s (context %q) imports %s (context %q) — "+
				"cross-context imports must target a sharedKernel package. Declare a "+
				"consumer-side interface and wire it in internal/bootstrap instead, or "+
				"extend sharedKernel deliberately.", self, selfCtx, dep, depCtx)
		}
	}
}

// TestCrossContextCycle pins the context-level dependency graph.
//
// R3 constrains which *packages* may be imported across contexts; this pins the
// resulting context→context edge set. It exists because the graph is not a DAG:
//
//	access → identity   (authentication reads the user aggregate)
//	identity → access   (tenant + invitations mint a session)
//
// access and identity are therefore mutually dependent and cannot be separated
// or extracted independently. That is accepted for now — it is recorded here so
// it stays visible, and so a *second* cycle (e.g. federation ↔ developer) fails
// the build instead of quietly appearing.
//
// A failure here means the coupling shape changed. Update the map only with a
// deliberate decision about the new edge.
func TestCrossContextCycle(t *testing.T) {
	want := map[string][]string{
		"access":     {"identity", "operations"},
		"developer":  {"access", "operations"},
		"federation": {"access", "identity", "operations"},
		"identity":   {"access", "operations"},
	}

	got := map[string]map[string]bool{}
	for _, p := range loadPackages(t) {
		selfCtx := contextOf(rel(p.ImportPath))
		if selfCtx == "" {
			continue
		}
		for _, imp := range p.Imports {
			depCtx := contextOf(rel(imp))
			if depCtx == "" || depCtx == selfCtx {
				continue
			}
			if got[selfCtx] == nil {
				got[selfCtx] = map[string]bool{}
			}
			got[selfCtx][depCtx] = true
		}
	}

	for from, targets := range got {
		var list []string
		for to := range targets {
			list = append(list, to)
		}
		sort.Strings(list)
		expected, ok := want[from]
		if !ok {
			t.Errorf("context %q gained cross-context dependencies %v — none were expected", from, list)
			continue
		}
		if strings.Join(list, ",") != strings.Join(expected, ",") {
			t.Errorf("context %q depends on %v, want %v", from, list, expected)
		}
	}
	for from := range want {
		if _, ok := got[from]; !ok {
			t.Errorf("context %q no longer has cross-context dependencies %v — "+
				"if the coupling was removed, delete its entry here", from, want[from])
		}
	}
}
